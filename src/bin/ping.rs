use log::{error, info};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout, Duration};
use tokio_postgres::NoTls;
use tokio_postgres::Row;
use tokio_postgres::Transaction;

use void::config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Init logger
    env_logger::init();

    info!("Starting ping");

    let cfg = config::read_config();

    // Connect to postgres
    let database_params = format!(
        "host={} user={} password={} dbname={}",
        cfg.database.host, cfg.database.user, cfg.database.password, cfg.database.dbname,
    );
    let (mut client, connection) = tokio_postgres::connect(&database_params, NoTls).await?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            error!("Connection error: {}", e);
        }
    });

    // Loading ping config
    let timeout_duration = Duration::from_millis(cfg.ping.timeout);
    let semaphore = Arc::new(Semaphore::new(cfg.ping.permits));
    let batch_size = cfg.ping.batch_size;
    let interval = Duration::from_secs(cfg.ping.interval);

    let mut round_id = 0;
    // Starts infinite loop
    loop {
        ping_round(&mut client, &semaphore, batch_size, timeout_duration).await?;
        info!(
            "Round {} finished. Waiting for {} seconds before the next round...",
            round_id,
            interval.as_secs()
        );
        sleep(interval).await;
        round_id += 1;
    }
}

// Runs batches of concurent ping requests against db ip addresses
// and update last_ping_timestamp to NOW() for each successful requests
async fn ping_round(
    client: &mut tokio_postgres::Client,
    semaphore: &Arc<Semaphore>,
    batch_size: i64,
    timeout_duration: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut offset = 0;
    loop {
        let transaction = client.transaction().await?;
        let rows = fetch_batch(&transaction, offset, batch_size).await?;
        if rows.is_empty() {
            break;
        }
        let updates = ping_batch(&rows, semaphore, timeout_duration).await?;
        update_batch(&transaction, updates).await?;
        transaction.commit().await?;
        offset += batch_size;
    }
    Ok(())
}

async fn ping_batch(
    rows: &[tokio_postgres::Row],
    semaphore: &Arc<Semaphore>,
    timeout_duration: Duration,
) -> Result<Vec<(String, i32)>, Box<dyn std::error::Error>> {
    let mut tasks = Vec::new();
    for row in rows {
        let address: String = row.get(0);
        let tcp_port: i32 = row.get(1);
        let semaphore = Arc::clone(&semaphore);

        tasks.push(tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap(); // Wait for a permit
            let socket_address: SocketAddr = format!("{}:{}", address, tcp_port).parse().unwrap();

            match timeout(timeout_duration, TcpStream::connect(&socket_address)).await {
                Ok(Ok(_)) => {
                    info!("{} on port {} is working", address, tcp_port);
                    Some((address, tcp_port))
                }
                Ok(Err(_)) | Err(_) => {
                    error!("{} on port {} is NOT WORKING...", address, tcp_port);
                    None
                }
            }
        }));
    }
    let mut updates = Vec::new();
    for task in tasks {
        if let Some(update) = task.await? {
            updates.push(update);
        }
    }

    Ok(updates)
}

async fn fetch_batch(
    transaction: &tokio_postgres::Transaction<'_>,
    offset: i64,
    limit: i64,
) -> Result<Vec<Row>, Box<dyn std::error::Error>> {
    let rows = transaction
        .query(
            "SELECT address, tcp_port FROM discv4.nodes LIMIT $1 OFFSET $2",
            &[&limit, &offset],
        )
        .await?;
    Ok(rows)
}

async fn update_batch(
    transaction: &Transaction<'_>,
    updates: Vec<(String, i32)>,
) -> Result<(), Box<dyn std::error::Error>> {
    for (address, tcp_port) in updates {
        transaction
            .execute(
                "UPDATE discv4.nodes SET last_ping_timestamp = NOW() WHERE address = $1 AND tcp_port = $2 AND (last_ping_timestamp IS NULL OR last_ping_timestamp < NOW())",
                &[&address, &tcp_port],
            )
            .await?;
    }
    Ok(())
}

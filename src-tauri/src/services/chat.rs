use std::collections::HashMap;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::mpsc;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use crate::AppState;

pub struct ChatManager {
    // Maps channel_id to a sender that pushes messages to the WebSocket
    pub connections: Mutex<HashMap<String, mpsc::UnboundedSender<String>>>,
}

impl ChatManager {
    pub fn new() -> Self {
        Self {
            connections: Mutex::new(HashMap::new()),
        }
    }
}

pub async fn join_channel(
    app: AppHandle,
    worker_url: String,
    channel_id: String,
) -> Result<(), String> {
    // FIX 1: Access ChatManager via AppState
    let app_state = app.state::<AppState>();
    let manager = &app_state.chat_manager;

    // Prevent duplicate connections
    if let Ok(conns) = manager.connections.lock() {
        if conns.contains_key(&channel_id) {
            return Ok(());
        }
    }

    // Convert HTTP/HTTPS URL to WS/WSS
    let ws_url = format!(
        "{}/ws/{}",
        worker_url.replace("https://", "wss://").replace("http://", "ws://"),
        channel_id
    );

    let (ws_stream, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .map_err(|e| format!("Failed to connect to gateway: {}", e))?;

    let (mut write, mut read) = ws_stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // Save the sender to our state
    if let Ok(mut conns) = manager.connections.lock() {
        conns.insert(channel_id.clone(), tx);
    }

    let app_clone = app.clone();
    let ch_id_clone = channel_id.clone();

    // Task 1: Read from WebSocket and emit to React Frontend
    tokio::spawn(async move {
        while let Some(msg) = read.next().await {
            match msg {
                // FIX 2: Handle Utf8Bytes/String conversion safely for newer tungstenite versions
                Ok(Message::Text(text)) => {
                    let _ = app_clone.emit(
                        "chat-message-received",
                        serde_json::json!({
                            "channel_id": ch_id_clone,
                            "payload": text.to_string()
                        }),
                    );
                }
                Ok(Message::Close(_)) => break,
                Err(_) => break,
                _ => {}
            }
        }
        // Cleanup on disconnect
        if let Some(state) = app_clone.try_state::<AppState>() {
            if let Ok(mut conns) = state.chat_manager.connections.lock() {
                conns.remove(&ch_id_clone);
            }
        }
    });

    // Task 2: Read from Rust mpsc channel and write to WebSocket
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            // FIX 2: Convert String to Utf8Bytes if required by newer tungstenite
            if write.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    tracing::info!(channel_id = %channel_id, "Joined real-time chat channel");
    Ok(())
}

pub async fn send_chat_message(
    app: AppHandle,
    channel_id: String,
    payload: String,
) -> Result<(), String> {
    // FIX 1: Access ChatManager via AppState
    let app_state = app.state::<AppState>();
    let manager = &app_state.chat_manager;
    
    if let Ok(conns) = manager.connections.lock() {
        if let Some(tx) = conns.get(&channel_id) {
            tx.send(payload).map_err(|e| e.to_string())?;
            return Ok(());
        }
    }
    Err("Not connected to this channel".into())
}
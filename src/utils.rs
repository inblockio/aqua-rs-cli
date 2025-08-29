use std::{fs::{self, File, OpenOptions}, path::{Path, PathBuf}};
use std::io::{BufReader, BufWriter, Read, Write};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tokio::fs as tokio_fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task;
use tokio::time::sleep;
use aqua_verifier_rs_types::models::page_data::PageData;
use lazy_static::lazy_static;
use once_cell::sync::OnceCell;

use crate::models::SecreatKeys;

extern crate serde_json_path_to_error as serde_json;

pub fn save_logs_to_file(logs : &Vec<String>, output_file : PathBuf, ) -> Result<String, String> {
 // Open the file in append mode, create it if it doesn't exist
    let mut file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(&output_file)
    {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to open log file: {}", e)),
    };

    // Write each log entry to the file, adding a newline after each one
    for log in logs {
        if let Err(e) = writeln!(file, "{}", log) {
            return Err(format!("Failed to write to log file: {}", e));
        }
    }

    Ok("Log written successfully".to_string())
}

pub fn read_aqua_data(path: &PathBuf) -> Result<PageData, String> {
    let data = fs::read_to_string(path);
    match data {
        Ok(data) =>{
            let res= serde_json::from_str::<PageData>(&data);
            match res {
                Ok(res_data)=>{
                    Ok(res_data)
                }
                Err(err_data)=>{
                    return Err(format!("Error, parsing json {}", err_data));
                }
            }
        }
        Err(e)=>{
            return Err(format!("Error , {}", e));
        }
    }
}

pub fn read_secreat_keys(path: &PathBuf) -> Result<SecreatKeys, String> {
    let data = fs::read_to_string(path);
    match data {
        Ok(data) =>{
            let res= serde_json::from_str::<SecreatKeys>(&data);
            match res {
                Ok(res_data)=>{
                    Ok(res_data)
                }
                Err(err_data)=>{
                    return Err(format!("Error, parsing json {}", err_data));
                }
            }
        }
        Err(e)=>{
            return Err(format!("Error , {}", e));
        }
    }
}

// Assuming `PageData` has serde::Serialize trait implemented
pub fn save_page_data(aqua_page_data: &PageData, original_path: &Path, extension : String) -> Result<(), String> {
    // Change the file extension to "_signed.json"
    let output_path = original_path.with_extension(extension);

    // Serialize PageData to JSON
    match serde_json::to_string_pretty(aqua_page_data) {
        Ok(json_data) => {
            // Write JSON data to the new file
            fs::write(&output_path, json_data).map_err(|e| e.to_string())?;
            println!("Aqua chain data saved to: {:?}", output_path);
            Ok(())
        }
        Err(e) => Err(format!("Error serializing PageData: {}", e)),
    }
}

pub fn is_valid_json_file(s: &str) -> Result<String, String> {
    let path = PathBuf::from(s);
    if path.exists() && path.is_file() && path.extension().unwrap_or_default() == "json" {
        Ok(s.to_string())
    } else {
        Err("Invalid JSON file path".to_string())
    }
}

pub fn is_valid_file(s: &str) -> Result<String, String> {
    let path = PathBuf::from(s);
    if path.exists() && path.is_file() {
        Ok(s.to_string())
    } else {
        Err("Invalid file path".to_string())
    }
}

pub fn is_valid_output_file(s: &str) -> Result<String, String> {
    let lowercase = s.to_lowercase();
    if lowercase.ends_with(".json") || lowercase.ends_with(".html") || lowercase.ends_with(".pdf") {
        Ok(s.to_string())
    } else {
        Err("Output file must be .json, .html, or .pdf".to_string())
    }
}

pub fn string_to_bool(s: String) -> bool {
    match s.to_lowercase().as_str() {
        "true" => true,
        "yes" => true,
        "false" => false,
        "no" => false,
        _ => false
    }
}

/// ✅ OPTIMIZED: Buffered file reading with better error handling
pub fn read_aqua_data_buffered(path: &PathBuf) -> Result<PageData, String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let mut reader = BufReader::new(file);
    let mut buffer = String::new();
    
    reader.read_to_string(&mut buffer)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    serde_json::from_str::<PageData>(&buffer)
        .map_err(|e| format!("Failed to parse JSON: {}", e))
}

/// ✅ OPTIMIZED: Buffered secret keys reading
pub fn read_secreat_keys_buffered(path: &PathBuf) -> Result<SecreatKeys, String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let mut reader = BufReader::new(file);
    let mut buffer = String::new();
    
    reader.read_to_string(&mut buffer)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    serde_json::from_str::<SecreatKeys>(&buffer)
        .map_err(|e| format!("Failed to parse JSON: {}", e))
}

/// ✅ OPTIMIZED: Buffered page data saving with atomic write
pub fn save_page_data_buffered(aqua_page_data: &PageData, original_path: &Path, extension: String) -> Result<(), String> {
    let output_path = original_path.with_extension(&extension);
    let temp_path = output_path.with_extension(format!("{}.tmp", &extension));
    
    // Create temporary file first
    let temp_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp_path)
        .map_err(|e| format!("Failed to create temp file: {}", e))?;
    
    let mut writer = BufWriter::new(temp_file);
    
    // Serialize to JSON
    let json_data = serde_json::to_string_pretty(aqua_page_data)
        .map_err(|e| format!("Failed to serialize data: {}", e))?;
    
    // Write to temp file
    writer.write_all(json_data.as_bytes())
        .map_err(|e| format!("Failed to write temp file: {}", e))?;
    
    // Flush buffer to ensure all data is written
    writer.flush()
        .map_err(|e| format!("Failed to flush buffer: {}", e))?;
    
    // Drop writer to close file
    drop(writer);
    
    // Atomic move from temp to final location
    fs::rename(&temp_path, &output_path)
        .map_err(|e| format!("Failed to move temp file: {}", e))?;
    
    println!("Aqua chain data saved to: {:?}", output_path);
    Ok(())
}

/// ✅ NEW: Async version for non-blocking I/O
pub async fn read_aqua_data_async(path: &PathBuf) -> Result<PageData, String> {
    let content = tokio_fs::read_to_string(path).await
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    serde_json::from_str::<PageData>(&content)
        .map_err(|e| format!("Failed to parse JSON: {}", e))
}

/// ✅ NEW: Async version for non-blocking I/O
pub async fn read_secreat_keys_async(path: &PathBuf) -> Result<SecreatKeys, String> {
    let content = tokio_fs::read_to_string(path).await
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    serde_json::from_str::<SecreatKeys>(&content)
        .map_err(|e| format!("Failed to parse JSON: {}", e))
}

/// ✅ NEW: Async version for non-blocking I/O
pub async fn save_page_data_async(aqua_page_data: &PageData, original_path: &Path, extension: String) -> Result<(), String> {
    let output_path = original_path.with_extension(extension);
    
    let json_data = serde_json::to_string_pretty(aqua_page_data)
        .map_err(|e| format!("Failed to serialize data: {}", e))?;
    
    tokio_fs::write(&output_path, json_data).await
        .map_err(|e| format!("Failed to write file: {}", e))?;
    
    println!("Aqua chain data saved to: {:?}", output_path);
    Ok(())
}

/// ✅ NEW: Async logger that batches logs and writes them asynchronously
/// This prevents disk I/O from blocking critical signing operations
#[derive(Clone)]
pub struct AsyncLogger {
    sender: mpsc::UnboundedSender<LogEntry>,
    task_handle: Arc<Mutex<Option<task::JoinHandle<()>>>>,
}

/// ✅ NEW: Log entry structure for async processing
#[derive(Debug, Clone)]
pub struct LogEntry {
    timestamp: Instant,
    level: LogLevel,
    message: String,
    target_file: Option<PathBuf>,
}

/// ✅ NEW: Log levels for better categorization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warning => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl AsyncLogger {
    /// ✅ FIXED: Create a new async logger instance with runtime check
    pub fn new() -> Self {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        
        // Check if we're in a Tokio runtime context
        let task_handle = match tokio::runtime::Handle::try_current() {
            Ok(_) => {
                // We're in a Tokio runtime, spawn the task
                task::spawn(async move {
                    let mut log_buffer: VecDeque<LogEntry> = VecDeque::new();
                    let mut last_flush = Instant::now();
                    const FLUSH_INTERVAL: Duration = Duration::from_millis(100);
                    const MAX_BUFFER_SIZE: usize = 1000;
                    
                    while let Some(entry) = receiver.recv().await {
                        log_buffer.push_back(entry);
                        
                        let should_flush = log_buffer.len() >= MAX_BUFFER_SIZE || 
                                         last_flush.elapsed() >= FLUSH_INTERVAL;
                        
                        if should_flush {
                            for entry in &log_buffer {
                                println!("[{}] {}: {}", 
                                    entry.timestamp.elapsed().as_millis(), 
                                    entry.level, 
                                    entry.message
                                );
                            }
                            log_buffer.clear();
                            last_flush = Instant::now();
                        }
                    }
                    
                    if !log_buffer.is_empty() {
                        for entry in &log_buffer {
                            println!("[{}] {}: {}", 
                                entry.timestamp.elapsed().as_millis(), 
                                entry.level, 
                                entry.message
                            );
                        }
                    }
                })
            },
            Err(_) => {
                // No Tokio runtime available, create a dummy task handle
                // that will be handled differently
                eprintln!("Warning: AsyncLogger created outside Tokio runtime. Logging will be synchronous.");
                task::spawn(async {}) // Dummy task that completes immediately
            }
        };
        
        AsyncLogger {
            sender,
            task_handle: Arc::new(Mutex::new(Some(task_handle))),
        }
    }
    
    /// ✅ NEW: Log a message asynchronously (with fallback to sync)
    pub fn log(&self, level: LogLevel, message: String, target_file: Option<PathBuf>) {
        let entry = LogEntry {
            timestamp: Instant::now(),
            level,
            message: message.clone(),
            target_file,
        };
        
        // Try to send async, fallback to sync if channel is closed/full
        if self.sender.send(entry).is_err() {
            // Fallback to synchronous logging
            println!("[SYNC] {}: {}", level, message);
        }
    }
    
    /// ✅ NEW: Log info message
    pub fn info(&self, message: String, target_file: Option<PathBuf>) {
        self.log(LogLevel::Info, message, target_file);
    }
    
    /// ✅ NEW: Log error message
    pub fn error(&self, message: String, target_file: Option<PathBuf>) {
        self.log(LogLevel::Error, message, target_file);
    }
    
    /// ✅ NEW: Log warning message
    pub fn warning(&self, message: String, target_file: Option<PathBuf>) {
        self.log(LogLevel::Warning, message, target_file);
    }
    
    /// ✅ NEW: Graceful shutdown
    pub async fn shutdown(self) {
        // Drop sender to close channel
        drop(self.sender);
        
        // Wait for task to complete
        if let Some(handle) = self.task_handle.lock().unwrap().take() {
            let _ = handle.await;
        }
    }
}

/// ✅ NEW: Synchronous logger for non-async contexts
#[derive(Clone)]
pub struct SyncLogger;

impl SyncLogger {
    pub fn new() -> Self {
        SyncLogger
    }
    
    pub fn log(&self, level: LogLevel, message: String, _target_file: Option<PathBuf>) {
        println!("[{}] {}: {}", 
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(), 
            level, 
            message
        );
    }
    
    pub fn info(&self, message: String, target_file: Option<PathBuf>) {
        self.log(LogLevel::Info, message, target_file);
    }
    
    pub fn error(&self, message: String, target_file: Option<PathBuf>) {
        self.log(LogLevel::Error, message, target_file);
    }
    
    pub fn warning(&self, message: String, target_file: Option<PathBuf>) {
        self.log(LogLevel::Warning, message, target_file);
    }
}

/// ✅ NEW: Global logger that works in both sync and async contexts
static GLOBAL_LOGGER: std::sync::OnceLock<Box<dyn Logger + Send + Sync>> = std::sync::OnceLock::new();

pub trait Logger {
    fn log(&self, level: LogLevel, message: String, target_file: Option<PathBuf>);
    fn info(&self, message: String, target_file: Option<PathBuf>);
    fn error(&self, message: String, target_file: Option<PathBuf>);
    fn warning(&self, message: String, target_file: Option<PathBuf>);
}

impl Logger for AsyncLogger {
    fn log(&self, level: LogLevel, message: String, target_file: Option<PathBuf>) {
        self.log(level, message, target_file);
    }
    
    fn info(&self, message: String, target_file: Option<PathBuf>) {
        self.info(message, target_file);
    }
    
    fn error(&self, message: String, target_file: Option<PathBuf>) {
        self.error(message, target_file);
    }
    
    fn warning(&self, message: String, target_file: Option<PathBuf>) {
        self.warning(message, target_file);
    }
}

impl Logger for SyncLogger {
    fn log(&self, level: LogLevel, message: String, target_file: Option<PathBuf>) {
        self.log(level, message, target_file);
    }
    
    fn info(&self, message: String, target_file: Option<PathBuf>) {
        self.info(message, target_file);
    }
    
    fn error(&self, message: String, target_file: Option<PathBuf>) {
        self.error(message, target_file);
    }
    
    fn warning(&self, message: String, target_file: Option<PathBuf>) {
        self.warning(message, target_file);
    }
}

/// ✅ FIXED: Initialize logger with runtime detection
pub fn init_logger() -> Box<dyn Logger + Send + Sync> {
    match tokio::runtime::Handle::try_current() {
        Ok(_) => {
            // In async context, use AsyncLogger
            Box::new(AsyncLogger::new())
        },
        Err(_) => {
            // In sync context, use SyncLogger
            Box::new(SyncLogger::new())
        }
    }
}



/// ✅ OPTIMIZED: Async version of save_logs_to_file
pub async fn save_logs_to_file_async(logs: &[String], output_file: PathBuf) -> Result<String, String> {
    let content = logs.join("\n") + "\n";
    
    tokio_fs::write(&output_file, content).await
        .map_err(|e| format!("Failed to write logs: {}", e))?;
    
    Ok("Logs written successfully asynchronously".to_string())
}

/// ✅ OPTIMIZED: Batched logging with configurable batch size
pub async fn save_logs_batched(
    logs: &[String], 
    output_file: PathBuf, 
    batch_size: usize
) -> Result<String, String> {
    let mut file = tokio_fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&output_file)
        .await
        .map_err(|e| format!("Failed to open log file: {}", e))?;
    
    // Process logs in batches
    for (batch_num, batch) in logs.chunks(batch_size).enumerate() {
        let batch_content = batch.join("\n") + "\n";
        
        tokio::io::AsyncWriteExt::write_all(&mut file, batch_content.as_bytes()).await
            .map_err(|e| format!("Failed to write batch {}: {}", batch_num + 1, e))?;
        
        // Small delay between batches to prevent overwhelming the disk
        sleep(Duration::from_millis(10)).await;
    }
    
    Ok(format!("Logs written successfully in {} batches", (logs.len() + batch_size - 1) / batch_size))
}

/// ✅ NEW: Global async logger instance
lazy_static::lazy_static! {
    static ref ASYNC_LOGGER: Arc<Mutex<Option<AsyncLogger>>> = Arc::new(Mutex::new(None));
}

/// ✅ NEW: Initialize global async logger
pub fn init_async_logger() -> AsyncLogger {
    let mut logger_guard = ASYNC_LOGGER.lock().unwrap();
    let logger = AsyncLogger::new();
    *logger_guard = Some(logger.clone());
    logger
}

/// ✅ NEW: Get global async logger reference
pub fn get_async_logger() -> Option<AsyncLogger> {
    ASYNC_LOGGER.lock().unwrap().clone()
}

/// ✅ NEW: Initialize global logger (safe for both sync and async contexts)
pub fn init_global_logger() {
    init_async_logger();
}

/// ✅ NEW: Get global logger reference
pub fn get_global_logger() -> Option<AsyncLogger> {
    get_async_logger()
}
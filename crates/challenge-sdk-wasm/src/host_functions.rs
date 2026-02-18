use alloc::vec;
use alloc::vec::Vec;

#[link(wasm_import_module = "platform_network")]
extern "C" {
    fn http_get(req_ptr: i32, req_len: i32, resp_ptr: i32, resp_len: i32) -> i32;
    fn http_post(req_ptr: i32, req_len: i32, resp_ptr: i32, resp_len: i32, extra: i32) -> i32;
    fn dns_resolve(req_ptr: i32, req_len: i32, resp_ptr: i32) -> i32;
}

#[link(wasm_import_module = "platform_storage")]
extern "C" {
    fn storage_get(key_ptr: i32, key_len: i32, value_ptr: i32) -> i32;
    fn storage_set(key_ptr: i32, key_len: i32, value_ptr: i32, value_len: i32) -> i32;
}

#[link(wasm_import_module = "platform_terminal")]
extern "C" {
    fn terminal_exec(cmd_ptr: i32, cmd_len: i32, result_ptr: i32, result_len: i32) -> i32;
    fn terminal_read_file(path_ptr: i32, path_len: i32, buf_ptr: i32, buf_len: i32) -> i32;
    fn terminal_write_file(path_ptr: i32, path_len: i32, data_ptr: i32, data_len: i32) -> i32;
    fn terminal_list_dir(path_ptr: i32, path_len: i32, buf_ptr: i32, buf_len: i32) -> i32;
    fn terminal_get_time() -> i64;
    fn terminal_random_seed(buf_ptr: i32, buf_len: i32) -> i32;
}

pub fn host_http_get(request: &[u8]) -> Result<Vec<u8>, i32> {
    let mut response_buf = vec![0u8; 65536];
    let status = unsafe {
        http_get(
            request.as_ptr() as i32,
            request.len() as i32,
            response_buf.as_mut_ptr() as i32,
            response_buf.len() as i32,
        )
    };
    if status < 0 {
        return Err(status);
    }
    response_buf.truncate(status as usize);
    Ok(response_buf)
}

pub fn host_http_post(request: &[u8], body: &[u8]) -> Result<Vec<u8>, i32> {
    let mut response_buf = vec![0u8; 65536];
    let status = unsafe {
        http_post(
            request.as_ptr() as i32,
            request.len() as i32,
            response_buf.as_mut_ptr() as i32,
            response_buf.len() as i32,
            body.len() as i32,
        )
    };
    if status < 0 {
        return Err(status);
    }
    response_buf.truncate(status as usize);
    Ok(response_buf)
}

pub fn host_dns_resolve(request: &[u8]) -> Result<Vec<u8>, i32> {
    let mut response_buf = vec![0u8; 4096];
    let status = unsafe {
        dns_resolve(
            request.as_ptr() as i32,
            request.len() as i32,
            response_buf.as_mut_ptr() as i32,
        )
    };
    if status < 0 {
        return Err(status);
    }
    response_buf.truncate(status as usize);
    Ok(response_buf)
}

pub fn host_storage_get(key: &[u8]) -> Result<Vec<u8>, i32> {
    let mut value_buf = vec![0u8; 65536];
    let status = unsafe {
        storage_get(
            key.as_ptr() as i32,
            key.len() as i32,
            value_buf.as_mut_ptr() as i32,
        )
    };
    if status < 0 {
        return Err(status);
    }
    value_buf.truncate(status as usize);
    Ok(value_buf)
}

pub fn host_storage_set(key: &[u8], value: &[u8]) -> Result<(), i32> {
    let status = unsafe {
        storage_set(
            key.as_ptr() as i32,
            key.len() as i32,
            value.as_ptr() as i32,
            value.len() as i32,
        )
    };
    if status < 0 {
        return Err(status);
    }
    Ok(())
}

pub fn host_terminal_exec(request: &[u8]) -> Result<Vec<u8>, i32> {
    let mut result_buf = vec![0u8; 262144];
    let status = unsafe {
        terminal_exec(
            request.as_ptr() as i32,
            request.len() as i32,
            result_buf.as_mut_ptr() as i32,
            result_buf.len() as i32,
        )
    };
    if status < 0 {
        return Err(status);
    }
    result_buf.truncate(status as usize);
    Ok(result_buf)
}

pub fn host_read_file(path: &[u8]) -> Result<Vec<u8>, i32> {
    let mut buf = vec![0u8; 262144];
    let status = unsafe {
        terminal_read_file(
            path.as_ptr() as i32,
            path.len() as i32,
            buf.as_mut_ptr() as i32,
            buf.len() as i32,
        )
    };
    if status < 0 {
        return Err(status);
    }
    buf.truncate(status as usize);
    Ok(buf)
}

pub fn host_write_file(path: &[u8], data: &[u8]) -> Result<(), i32> {
    let status = unsafe {
        terminal_write_file(
            path.as_ptr() as i32,
            path.len() as i32,
            data.as_ptr() as i32,
            data.len() as i32,
        )
    };
    if status < 0 {
        return Err(status);
    }
    Ok(())
}

pub fn host_list_dir(path: &[u8]) -> Result<Vec<u8>, i32> {
    let mut buf = vec![0u8; 65536];
    let status = unsafe {
        terminal_list_dir(
            path.as_ptr() as i32,
            path.len() as i32,
            buf.as_mut_ptr() as i32,
            buf.len() as i32,
        )
    };
    if status < 0 {
        return Err(status);
    }
    buf.truncate(status as usize);
    Ok(buf)
}

pub fn host_get_time() -> i64 {
    unsafe { terminal_get_time() }
}

pub fn host_random_seed(buf: &mut [u8]) -> Result<(), i32> {
    let status = unsafe { terminal_random_seed(buf.as_mut_ptr() as i32, buf.len() as i32) };
    if status < 0 {
        return Err(status);
    }
    Ok(())
}

#[link(wasm_import_module = "platform_sandbox")]
extern "C" {
    fn sandbox_exec(req_ptr: i32, req_len: i32, resp_ptr: i32, resp_len: i32) -> i32;
    fn get_timestamp() -> i64;
    fn log_message(level: i32, msg_ptr: i32, msg_len: i32);
}

pub fn host_sandbox_exec(request: &[u8]) -> Result<Vec<u8>, i32> {
    let mut response_buf = vec![0u8; 262144];
    let status = unsafe {
        sandbox_exec(
            request.as_ptr() as i32,
            request.len() as i32,
            response_buf.as_mut_ptr() as i32,
            response_buf.len() as i32,
        )
    };
    if status < 0 {
        return Err(status);
    }
    response_buf.truncate(status as usize);
    Ok(response_buf)
}

pub fn host_get_timestamp() -> i64 {
    unsafe { get_timestamp() }
}

pub fn host_log(level: u8, msg: &str) {
    unsafe { log_message(level as i32, msg.as_ptr() as i32, msg.len() as i32) }
}

#[link(wasm_import_module = "platform_consensus")]
extern "C" {
    fn consensus_get_epoch() -> i64;
    fn consensus_get_validators(buf_ptr: i32, buf_len: i32) -> i32;
    fn consensus_propose_weight(uid: i32, weight: i32) -> i32;
    fn consensus_get_votes(buf_ptr: i32, buf_len: i32) -> i32;
    fn consensus_get_state_hash(buf_ptr: i32) -> i32;
    fn consensus_get_submission_count() -> i32;
    fn consensus_get_block_height() -> i64;
}

pub fn host_consensus_get_epoch() -> i64 {
    unsafe { consensus_get_epoch() }
}

pub fn host_consensus_get_validators() -> Result<Vec<u8>, i32> {
    let mut buf = vec![0u8; 65536];
    let status = unsafe { consensus_get_validators(buf.as_mut_ptr() as i32, buf.len() as i32) };
    if status < 0 {
        return Err(status);
    }
    buf.truncate(status as usize);
    Ok(buf)
}

pub fn host_consensus_propose_weight(uid: i32, weight: i32) -> Result<(), i32> {
    let status = unsafe { consensus_propose_weight(uid, weight) };
    if status < 0 {
        return Err(status);
    }
    Ok(())
}

pub fn host_consensus_get_votes() -> Result<Vec<u8>, i32> {
    let mut buf = vec![0u8; 65536];
    let status = unsafe { consensus_get_votes(buf.as_mut_ptr() as i32, buf.len() as i32) };
    if status < 0 {
        return Err(status);
    }
    buf.truncate(status as usize);
    Ok(buf)
}

pub fn host_consensus_get_state_hash() -> Result<[u8; 32], i32> {
    let mut buf = [0u8; 32];
    let status = unsafe { consensus_get_state_hash(buf.as_mut_ptr() as i32) };
    if status < 0 {
        return Err(status);
    }
    Ok(buf)
}

pub fn host_consensus_get_submission_count() -> i32 {
    unsafe { consensus_get_submission_count() }
}

pub fn host_consensus_get_block_height() -> i64 {
    unsafe { consensus_get_block_height() }
}

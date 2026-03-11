use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Full OpenAI-compatible chat completion request.
/// The challenge WASM builds this completely; the host just proxies it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LlmRequest {
    pub model: String,
    pub messages: Vec<LlmMessage>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub frequency_penalty: Option<f32>,
    pub presence_penalty: Option<f32>,
    pub stop: Option<Vec<String>>,
    /// OpenAI function calling / tools
    pub tools: Option<Vec<Tool>>,
    pub tool_choice: Option<ToolChoice>,
    pub response_format: Option<ResponseFormat>,
}

impl LlmRequest {
    pub fn simple(model: &str, messages: Vec<LlmMessage>, max_tokens: u32) -> Self {
        Self {
            model: String::from(model),
            messages,
            max_tokens: Some(max_tokens),
            temperature: Some(0.1),
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
            stop: None,
            tools: None,
            tool_choice: None,
            response_format: None,
        }
    }

    pub fn with_tools(
        model: &str,
        messages: Vec<LlmMessage>,
        tools: Vec<Tool>,
        max_tokens: u32,
    ) -> Self {
        Self {
            model: String::from(model),
            messages,
            max_tokens: Some(max_tokens),
            temperature: Some(0.1),
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
            stop: None,
            tools: Some(tools),
            tool_choice: Some(ToolChoice::Auto),
            response_format: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LlmMessage {
    pub role: String,
    pub content: Option<String>,
    pub name: Option<String>,
    pub tool_calls: Option<Vec<ToolCall>>,
    pub tool_call_id: Option<String>,
}

impl LlmMessage {
    pub fn system(content: &str) -> Self {
        Self {
            role: String::from("system"),
            content: Some(String::from(content)),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    pub fn user(content: &str) -> Self {
        Self {
            role: String::from("user"),
            content: Some(String::from(content)),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    pub fn assistant(content: &str) -> Self {
        Self {
            role: String::from("assistant"),
            content: Some(String::from(content)),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    pub fn assistant_tool_calls(tool_calls: Vec<ToolCall>) -> Self {
        Self {
            role: String::from("assistant"),
            content: None,
            name: None,
            tool_calls: Some(tool_calls),
            tool_call_id: None,
        }
    }

    pub fn tool(tool_call_id: &str, content: &str) -> Self {
        Self {
            role: String::from("tool"),
            content: Some(String::from(content)),
            name: None,
            tool_calls: None,
            tool_call_id: Some(String::from(tool_call_id)),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tool {
    #[serde(rename = "type")]
    pub tool_type: String,
    pub function: FunctionDef,
}

impl Tool {
    pub fn function(name: &str, description: &str, parameters: &str) -> Self {
        Self {
            tool_type: String::from("function"),
            function: FunctionDef {
                name: String::from(name),
                description: Some(String::from(description)),
                parameters: Some(String::from(parameters)),
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionDef {
    pub name: String,
    pub description: Option<String>,
    /// JSON Schema string for the function parameters
    pub parameters: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ToolChoice {
    Auto,
    None,
    Required,
    Specific { function: ToolChoiceFunction },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolChoiceFunction {
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseFormat {
    #[serde(rename = "type")]
    pub format_type: String,
}

impl ResponseFormat {
    pub fn json() -> Self {
        Self {
            format_type: String::from("json_object"),
        }
    }

    pub fn text() -> Self {
        Self {
            format_type: String::from("text"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub call_type: String,
    pub function: FunctionCall,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

/// Response from the host LLM proxy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LlmResponse {
    pub content: Option<String>,
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,
    pub usage: Option<LlmUsage>,
    pub finish_reason: Option<String>,
}

impl LlmResponse {
    pub fn text(&self) -> &str {
        self.content.as_deref().unwrap_or("")
    }

    pub fn has_tool_calls(&self) -> bool {
        !self.tool_calls.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LlmUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

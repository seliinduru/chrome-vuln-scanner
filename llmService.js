class LLMService {
    constructor() {
        this.apiKey = null;
        this.apiUrl = "https://openrouter.ai/api/v1/chat/completions";
        // List of free models on OpenRouter
        this.models = [
            { id: "xiaomi/mimo-v2-flash:free", name: "Xiaomi Mimo V2 Flash (Free)" },
            { id: "nvidia/nemotron-3-nano-30b-a3b:free", name: "Nvidia Nemotron 3 Nano (Free)" },
            { id: "mistralai/devstral-2512:free", name: "Mistral Devstral 2512 (Free)" },
            { id: "nex-agi/deepseek-v3.1-nex-n1:free", name: "DeepSeek V3.1 Nex (Free)" },
            { id: "amazon/nova-2-lite-v1:free", name: "Amazon Nova 2 Lite (Free)" },
            { id: "arcee-ai/trinity-mini:free", name: "Arcee Trinity Mini (Free)" },
            { id: "tngtech/tng-r1t-chimera:free", name: "TNG R1T Chimera (Free)" },
            { id: "allenai/olmo-3-32b-think:free", name: "AllenAI OLMo 3 32B (Free)" },
            { id: "kwaipilot/kat-coder-pro:free", name: "KwaiPilot Kat Coder Pro (Free)" },
            { id: "nvidia/nemotron-nano-12b-v2-vl:free", name: "Nvidia Nemotron Nano 12B (Free)" },
            { id: "alibaba/tongyi-deepresearch-30b-a3b:free", name: "Alibaba Tongyi DeepResearch (Free)" },
            { id: "nvidia/nemotron-nano-9b-v2:free", name: "Nvidia Nemotron Nano 9B (Free)" },
            { id: "openai/gpt-oss-120b:free", name: "GPT OSS 120B (Free)" },
            { id: "openai/gpt-oss-20b:free", name: "GPT OSS 20B (Free)" },
            { id: "z-ai/glm-4.5-air:free", name: "GLM 4.5 Air (Free)" },
            { id: "qwen/qwen3-coder:free", name: "Qwen3 Coder (Free)" },
            { id: "moonshotai/kimi-k2:free", name: "Moonshot Kimi K2 (Free)" },
            { id: "google/gemma-3n-e2b-it:free", name: "Gemma 3N E2B (Free)" },
            { id: "tngtech/deepseek-r1t2-chimera:free", name: "DeepSeek R1T2 Chimera (Free)" },
            { id: "google/gemma-3n-e4b-it:free", name: "Gemma 3N E4B (Free)" },
            { id: "qwen/qwen3-4b:free", name: "Qwen3 4B (Free)" },
            { id: "qwen/qwen3-235b-a22b:free", name: "Qwen3 235B (Free)" },
            { id: "tngtech/deepseek-r1t-chimera:free", name: "DeepSeek R1T Chimera (Free)" },
            { id: "mistralai/mistral-small-3.1-24b-instruct:free", name: "Mistral Small 3.1 (Free)" },
            { id: "google/gemma-3-4b-it:free", name: "Gemma 3 4B (Free)" },
            { id: "google/gemma-3-12b-it:free", name: "Gemma 3 12B (Free)" },
            { id: "google/gemma-3-27b-it:free", name: "Gemma 3 27B (Free)" },
            { id: "google/gemini-2.0-flash-exp:free", name: "Gemini 2.0 Flash Exp (Free)" },
            { id: "meta-llama/llama-3.3-70b-instruct:free", name: "Llama 3.3 70B (Free)" },
            { id: "meta-llama/llama-3.2-3b-instruct:free", name: "Llama 3.2 3B (Free)" },
            { id: "nousresearch/hermes-3-llama-3.1-405b:free", name: "Hermes 3 Llama 3.1 405B (Free)" },
            { id: "mistralai/mistral-7b-instruct:free", name: "Mistral 7B Instruct (Free)" }
        ];
    }

    getAvailableModels() {
        return this.models;
    }

    async loadConfig() {
        try {
            const response = await fetch(chrome.runtime.getURL('.env'));
            const text = await response.text();
            const match = text.match(/OPENROUTER_API_KEY=(.*)/);
            if (match && match[1]) {
                this.apiKey = match[1].trim();
            }
        } catch (error) {
            console.error("Failed to load .env file:", error);
        }
    }

    // Simple hash function for cache keys
    async generateHash(str) {
        const msgBuffer = new TextEncoder().encode(str);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    async getSuggestions(vulns, modelId) {
        if (!this.apiKey) {
            await this.loadConfig();
        }

        if (!this.apiKey || this.apiKey === 'your_api_key_here') {
            return { error: "API Key not configured. Please check .env file." };
        }

        if (!vulns || vulns.length === 0) {
            return { error: "No vulnerabilities to analyze." };
        }

        const selectedModel = modelId || this.models[0].id;

        // Prepare a detailed prompt with evidence
        const vulnDetails = vulns.map((v, index) => {
            let evidenceStr = "No specific code snippet available.";
            if (v.evidence) {
                evidenceStr = typeof v.evidence === 'object' ? JSON.stringify(v.evidence, null, 2) : v.evidence;
            }
            
            return `
--- VULNERABILITY #${index + 1} ---
Type: ${v.type}
Severity: ${v.severity}
Location: ${v.location}
Description: ${v.description || 'N/A'}
Evidence/Code Snippet:
\`\`\`
${evidenceStr}
\`\`\`
`;
        }).join('\n');

        // Generate cache key based on model and vulnerability details
        const cacheKeySource = `${selectedModel}:${vulnDetails}`;
        const cacheKey = await this.generateHash(cacheKeySource);
        
        // Check LocalStorage Cache
        const cachedResult = localStorage.getItem(cacheKey);
        if (cachedResult) {
            console.log("Returning cached LLM response for key:", cacheKey);
            return { content: cachedResult, fromCache: true };
        }

        const prompt = `
You are a Senior Web Security Engineer. I have detected the following vulnerabilities on a webpage. 
For each vulnerability, I am providing the type, location, description, and the specific code snippet (evidence) where it was found.

Your task is to:
1. Analyze the provided code snippet/evidence.
2. Explain why this is a vulnerability in this specific context.
3. Provide a concrete, secure code example to fix it.

Vulnerabilities Detected:
${vulnDetails}

Format your response as HTML. Use <h3> for vulnerability titles, <p> for explanations, and <pre><code> for code blocks.
Group the response clearly by vulnerability.
`;

        try {
            const response = await fetch(this.apiUrl, {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${this.apiKey}`,
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/seliinduru/chrome-vuln-scanner",
                    "X-Title": "Chrome Vuln Scanner"
                },
                body: JSON.stringify({
                    "model": selectedModel,
                    "messages": [
                        { "role": "user", "content": prompt }
                    ]
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(`API Error: ${errorData.error?.message || response.statusText}`);
            }

            const data = await response.json();
            const content = data.choices[0].message.content;

            // Save to Cache
            try {
                localStorage.setItem(cacheKey, content);
            } catch (e) {
                console.warn("Failed to save to localStorage (quota exceeded?):", e);
            }

            return { content: content, fromCache: false };

        } catch (error) {
            console.error("LLM Request failed:", error);
            return { error: error.message };
        }
    }

    async analyzeVuln(vuln, modelId) {
        const result = await this.getSuggestions([vuln], modelId);
        if (result.error) {
            throw new Error(result.error);
        }
        return result.content;
    }
}

// Export instance
window.llmService = new LLMService();
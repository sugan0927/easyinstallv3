cat > src/index.ts << 'EOF'
import { Hono } from 'hono';
import { EASYINSTALL_SCRIPT } from './script';

const app = new Hono();

// Serve the bash script
app.get('/script', (c) => {
    return new Response(EASYINSTALL_SCRIPT, {
        headers: {
            'Content-Type': 'text/plain',
            'Content-Disposition': 'attachment; filename="easyinstall.sh"'
        }
    });
});

// View script with line numbers
app.get('/script/view', (c) => {
    const lines = EASYINSTALL_SCRIPT.split('\n');
    const numberedContent = lines.map((line, index) => 
        `${(index + 1).toString().padStart(4, ' ')} | ${line}`
    ).join('\n');
    
    return new Response(numberedContent, {
        headers: { 'Content-Type': 'text/plain' }
    });
});

// Main webpage
app.get('/', (c) => {
    const baseUrl = new URL(c.req.url).origin;
    
    return c.html(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>EasyInstall Script Server</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; }
                body { 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .container {
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    padding: 40px;
                    max-width: 800px;
                    width: 90%;
                }
                h1 { 
                    color: #333;
                    margin-bottom: 10px;
                    font-size: 2em;
                }
                .subtitle {
                    color: #666;
                    margin-bottom: 30px;
                    border-bottom: 2px solid #f0f0f0;
                    padding-bottom: 20px;
                }
                .url-box {
                    background: #f5f5f5;
                    border-radius: 10px;
                    padding: 15px;
                    margin: 20px 0;
                    font-family: monospace;
                    word-break: break-all;
                }
                .command {
                    background: #1e1e1e;
                    color: #fff;
                    border-radius: 10px;
                    padding: 15px;
                    margin: 10px 0;
                    font-family: monospace;
                    position: relative;
                }
                .copy-btn {
                    position: absolute;
                    top: 10px;
                    right: 10px;
                    background: #4CAF50;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    padding: 5px 10px;
                    cursor: pointer;
                    font-size: 12px;
                }
                .copy-btn:hover {
                    background: #45a049;
                }
                .note {
                    background: #fff3cd;
                    border-left: 4px solid #ffc107;
                    padding: 15px;
                    margin: 20px 0;
                    border-radius: 5px;
                }
                .button {
                    display: inline-block;
                    background: #667eea;
                    color: white;
                    text-decoration: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    margin: 5px;
                    transition: background 0.3s;
                }
                .button:hover {
                    background: #764ba2;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🚀 EasyInstall Script Server</h1>
                <div class="subtitle">Run installation scripts directly from Cloudflare Workers</div>
                
                <div class="url-box">
                    <strong>Script URL:</strong><br>
                    ${baseUrl}/script
                </div>
                
                <h3>📥 Download & Run:</h3>
                
                <div class="command">
                    # Run directly (recommended)
                    curl -s ${baseUrl}/script | bash
                    <button class="copy-btn" onclick="copyCommand('curl -s ${baseUrl}/script | bash')">Copy</button>
                </div>
                
                <div class="command">
                    # Download and execute
                    curl -o easyinstall.sh ${baseUrl}/script
                    chmod +x easyinstall.sh
                    ./easyinstall.sh nginx
                    <button class="copy-btn" onclick="copyCommand('curl -o easyinstall.sh ${baseUrl}/script && chmod +x easyinstall.sh && ./easyinstall.sh')">Copy</button>
                </div>
                
                <div class="command">
                    # Install specific package
                    curl -s ${baseUrl}/script | bash -s nodejs
                    <button class="copy-btn" onclick="copyCommand('curl -s ${baseUrl}/script | bash -s nodejs')">Copy</button>
                </div>
                
                <div class="note">
                    <strong>⚠️ Note:</strong> The script runs on your local machine, not on Cloudflare. 
                    Make sure you have sudo access if installing system packages.
                </div>
                
                <div style="text-align: center; margin-top: 30px;">
                    <a href="/script" class="button" download>📄 Download Script</a>
                    <a href="/script/view" class="button">👁️ View Script</a>
                </div>
            </div>
            
            <script>
                function copyCommand(cmd) {
                    navigator.clipboard.writeText(cmd).then(() => {
                        alert('Command copied to clipboard!');
                    });
                }
            </script>
        </body>
        </html>
    `);
});

// API endpoint
app.get('/api/info', (c) => {
    const baseUrl = new URL(c.req.url).origin;
    
    return c.json({
        name: 'easyinstall-worker',
        version: '1.0.0',
        script_url: `${baseUrl}/script`,
        script_size: EASYINSTALL_SCRIPT.length,
        script_lines: EASYINSTALL_SCRIPT.split('\n').length,
        commands: {
            direct: `curl -s ${baseUrl}/script | bash`,
            download: `curl -o easyinstall.sh ${baseUrl}/script`,
            with_package: `curl -s ${baseUrl}/script | bash -s [package-name]`
        }
    });
});

export default app;
EOF

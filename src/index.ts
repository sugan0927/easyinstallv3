cat > src/index.ts << 'EOF'
import { Hono } from 'hono';

const app = new Hono();

// Script content को variable में store करें
const SCRIPT_CONTENT = `#!/bin/bash
# EasyInstall v3 - Main Installation Script
# This script will be fetched and executed by the client

echo "EasyInstall Script Started"
echo "Fetching package information..."

# Function to detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)     echo "Linux";;
        Darwin*)    echo "macOS";;
        CYGWIN*)    echo "Windows";;
        MINGW*)     echo "Windows";;
        *)          echo "Unknown";;
    esac
}

# Function to detect package manager
detect_package_manager() {
    if command -v apt &> /dev/null; then
        echo "apt"
    elif command -v yum &> /dev/null; then
        echo "yum"
    elif command -v dnf &> /dev/null; then
        echo "dnf"
    elif command -v pacman &> /dev/null; then
        echo "pacman"
    elif command -v brew &> /dev/null; then
        echo "brew"
    else
        echo "unknown"
    fi
}

# Main installation logic
main() {
    echo "OS: $(detect_os)"
    echo "Package Manager: $(detect_package_manager)"
    
    # Get package name from argument or prompt
    PACKAGE_NAME=${1:-"default-package"}
    
    echo "Installing package: $PACKAGE_NAME"
    
    # Add your installation logic here
    case $(detect_package_manager) in
        apt)
            sudo apt update && sudo apt install -y "$PACKAGE_NAME"
            ;;
        yum|dnf)
            sudo yum install -y "$PACKAGE_NAME"
            ;;
        pacman)
            sudo pacman -S --noconfirm "$PACKAGE_NAME"
            ;;
        brew)
            brew install "$PACKAGE_NAME"
            ;;
        *)
            echo "No supported package manager found"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
`;

// Route to get the script
app.get('/script', (c) => {
    return new Response(SCRIPT_CONTENT, {
        headers: {
            'Content-Type': 'text/plain',
            'Content-Disposition': 'attachment; filename="easyinstall.sh"'
        }
    });
});

// Route to get script with line numbers (for viewing)
app.get('/script/view', (c) => {
    const lines = SCRIPT_CONTENT.split('\n');
    const numberedContent = lines.map((line, index) => 
        `${(index + 1).toString().padStart(4, ' ')} | ${line}`
    ).join('\n');
    
    return new Response(numberedContent, {
        headers: { 'Content-Type': 'text/plain' }
    });
});

// Main route
app.get('/', (c) => {
    return c.html(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>EasyInstall Script Server</title>
            <style>
                body { font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px; }
                pre { background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }
                button { padding: 10px 20px; background: #0070f3; color: white; border: none; border-radius: 5px; cursor: pointer; }
            </style>
        </head>
        <body>
            <h1>EasyInstall Script Server</h1>
            <p>Your installation script is available at:</p>
            
            <h3>Direct Script URL:</h3>
            <pre>${c.req.url}script</pre>
            
            <h3>Download and run:</h3>
            <pre>curl -s ${c.req.url}script | bash</pre>
            
            <h3>Or save and run:</h3>
            <pre>curl -o easyinstall.sh ${c.req.url}script
chmod +x easyinstall.sh
./easyinstall.sh</pre>

            <button onclick="copyCommands()">Copy Commands</button>
            
            <h3>View Script Content:</h3>
            <a href="/script/view" target="_blank">View Full Script</a>
            
            <script>
            function copyCommands() {
                const text = \`# Download and run directly:
curl -s ${c.req.url}script | bash

# Or save and run:
curl -o easyinstall.sh ${c.req.url}script
chmod +x easyinstall.sh
./easyinstall.sh\`;
                
                navigator.clipboard.writeText(text);
                alert('Commands copied to clipboard!');
            }
            </script>
        </body>
        </html>
    `);
});

// API endpoint to get script info
app.get('/api/script-info', (c) => {
    return c.json({
        name: 'easyinstall.sh',
        version: '3.0',
        size: SCRIPT_CONTENT.length,
        lines: SCRIPT_CONTENT.split('\n').length,
        url: `${c.req.url}script`,
        downloadCommand: `curl -s ${c.req.url}script | bash`
    });
});

export default app;
EOF

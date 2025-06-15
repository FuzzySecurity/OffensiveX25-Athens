const vscode = require('vscode');

/**
 * This is the main entry point for the Starlight VS Code extension.
 * The activate function is called by VS Code when the extension is activated.
 * @param {vscode.ExtensionContext} context - The extension context provided by VS Code
 */
function activate(context) {
    // Log extension activation and environment details for reference/debugging
    console.log('Starlight extension is now active!');
    const startupTime = new Date().toISOString();
    console.log('=== Starlight Extension Startup ===');
    console.log(`Startup Time: ${startupTime}`);
    console.log(`Workspace: ${vscode.workspace.name || 'No workspace'}`);
    console.log(`Session ID: ${vscode.env.sessionId}`);
    console.log('Nothing passes door and window here save moonlight and starlight');
    console.log('===================================');

    // Register the "Hello World" command
    // This command can be invoked via the Command Palette or keybinding
    let helloWorldDisposable = vscode.commands.registerCommand('starlight.helloWorld', function () {
        // Show an information message to the user
        vscode.window.showInformationMessage('Hello World from Starlight!');
    });

    // Ensure the command is disposed of when the extension is deactivated
    context.subscriptions.push(helloWorldDisposable);
}

/**
 * This function is called when the extension is deactivated.
 * Used for cleanup logic if needed (none required for this minimal example).
 */
function deactivate() {
    // No cleanup required
}

// Export activate and deactivate functions for VS Code to use
module.exports = {
    activate,
    deactivate
}; 
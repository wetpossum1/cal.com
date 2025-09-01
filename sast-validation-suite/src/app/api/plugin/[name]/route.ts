import { NextRequest, NextResponse } from 'next/server';
import path from 'path';
import { promises as fs } from 'fs';

// A06: VULNERABLE AND OUTDATED COMPONENTS - Hard Level
// VULNERABLE: Dynamic component loading with user input
// SAST should detect: Dynamic require/import with user-controlled input

export async function GET(
  request: NextRequest,
  { params }: { params: { name: string } }
) {
  try {
    const pluginName = params.name; // TAINT SOURCE: user input from URL
    
    // Flows through validation that might be bypassed
    const sanitizedName = validatePluginName(pluginName);
    const plugin = await loadPlugin(sanitizedName);
    
    if (!plugin) {
      return NextResponse.json({ error: 'Plugin not found' }, { status: 404 });
    }
    
    // Execute plugin code
    const result = await plugin.execute();
    
    return NextResponse.json({
      plugin: sanitizedName,
      result: result,
      version: plugin.version || 'unknown'
    });
    
  } catch (error: any) {
    return NextResponse.json({
      error: 'Plugin execution failed',
      message: error.message
    }, { status: 500 });
  }
}

// VULNERABLE: Plugin name validation that can be bypassed
function validatePluginName(name: string): string {
  // Basic validation that looks secure but can be bypassed
  if (!name || name.length < 1) {
    throw new Error('Invalid plugin name');
  }
  
  // VULNERABLE: Insufficient path traversal protection
  if (name.includes('..')) {
    throw new Error('Path traversal detected');
  }
  
  // VULNERABLE: Only checks for some dangerous patterns
  const dangerousPatterns = ['/etc/', '/proc/', 'node_modules'];
  for (const pattern of dangerousPatterns) {
    if (name.includes(pattern)) {
      throw new Error('Dangerous path detected');
    }
  }
  
  // Returns user input after insufficient validation
  return name;
}

// VULNERABLE: Dynamic module loading
async function loadPlugin(name: string) {
  try {
    // VULNERABLE: Dynamic require with user input
    // This could load arbitrary modules outside the intended plugin directory
    const pluginPath = `./plugins/${name}`;
    
    // SINK: Dynamic import of user-controlled module path
    const plugin = require(pluginPath);
    
    return plugin;
    
  } catch (error) {
    // Try alternative loading methods that are also vulnerable
    return await loadPluginAlternative(name);
  }
}

// VULNERABLE: Alternative loading method with different attack vectors
async function loadPluginAlternative(name: string) {
  try {
    // VULNERABLE: File system access with user input
    const pluginDir = path.join(process.cwd(), 'plugins', name);
    const pluginFile = path.join(pluginDir, 'index.js');
    
    // Check if plugin exists
    await fs.access(pluginFile);
    
    // VULNERABLE: Dynamic import with constructed path
    const plugin = await import(pluginFile);
    
    return plugin.default || plugin;
    
  } catch (error) {
    // VULNERABLE: Fallback to even more dangerous loading
    return loadPluginFromNodeModules(name);
  }
}

// VULNERABLE: Loading from node_modules allows arbitrary package execution
async function loadPluginFromNodeModules(name: string) {
  try {
    // VULNERABLE: Direct require of user input - can load any npm package
    const plugin = require(name);
    
    return {
      execute: () => plugin,
      version: plugin.version || 'unknown'
    };
    
  } catch (error) {
    throw new Error(`Plugin ${name} not found`);
  }
}

// VULNERABLE: Plugin execution endpoint with code injection
export async function POST(
  request: NextRequest,
  { params }: { params: { name: string } }
) {
  try {
    const { code, args = [] } = await request.json();
    const pluginName = params.name;
    
    if (!code) {
      return NextResponse.json({ error: 'Code parameter is required' }, { status: 400 });
    }
    
    // VULNERABLE: Dynamic code execution
    const plugin = await loadPlugin(pluginName);
    
    if (!plugin) {
      return NextResponse.json({ error: 'Plugin not found' }, { status: 404 });
    }
    
    // VULNERABLE: eval() with user-controlled code
    const result = eval(`
      (function(plugin, args) {
        ${code}
      })(plugin, args)
    `);
    
    return NextResponse.json({
      plugin: pluginName,
      executionResult: result,
      args: args
    });
    
  } catch (error: any) {
    return NextResponse.json({
      error: 'Code execution failed',
      message: error.message
    }, { status: 500 });
  }
}
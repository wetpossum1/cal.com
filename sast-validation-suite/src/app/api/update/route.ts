import { NextRequest, NextResponse } from 'next/server';

// A08: SOFTWARE AND DATA INTEGRITY FAILURES - Medium Level
// VULNERABLE: Unsigned code execution and unsafe updates
// SAST should detect: Remote code execution, unsigned package installation

export async function POST(request: NextRequest) {
  try {
    const { updateUrl, packageName, version } = await request.json();
    
    if (!updateUrl) {
      return NextResponse.json({ error: 'Update URL is required' }, { status: 400 });
    }
    
    // VULNERABLE: Downloads and executes code without verification
    const updateResult = await downloadAndInstallUpdate(updateUrl, packageName, version);
    
    return NextResponse.json({
      message: 'Update completed successfully',
      updateUrl: updateUrl,
      result: updateResult
    });
    
  } catch (error: any) {
    return NextResponse.json({
      error: 'Update failed',
      message: error.message
    }, { status: 500 });
  }
}

// VULNERABLE: Update process without integrity verification
async function downloadAndInstallUpdate(url: string, packageName?: string, version?: string) {
  // VULNERABLE: Downloads from arbitrary URLs
  const updateCode = await downloadUpdate(url);
  
  if (packageName) {
    // VULNERABLE: Dynamic package installation
    await installPackage(packageName, version);
  }
  
  // VULNERABLE: Execute downloaded code without verification
  const result = await executeUpdate(updateCode);
  
  return result;
}

async function downloadUpdate(url: string): Promise<string> {
  try {
    // VULNERABLE: Fetches from user-controlled URL
    const response = await fetch(url);
    
    if (!response.ok) {
      throw new Error(`Failed to download update: ${response.status}`);
    }
    
    const updateCode = await response.text();
    
    // VULNERABLE: No signature or checksum verification
    // VULNERABLE: No source verification
    
    return updateCode;
    
  } catch (error) {
    throw new Error(`Update download failed: ${error.message}`);
  }
}

// VULNERABLE: Dynamic package installation without verification
async function installPackage(packageName: string, version?: string) {
  const { exec } = require('child_process');
  
  // VULNERABLE: Command injection through package name
  const installCommand = version 
    ? `npm install ${packageName}@${version}` 
    : `npm install ${packageName}`;
  
  return new Promise((resolve, reject) => {
    // VULNERABLE: Executes npm command with user input
    exec(installCommand, (error: any, stdout: string, stderr: string) => {
      if (error) {
        reject(error);
      } else {
        resolve({ stdout, stderr });
      }
    });
  });
}

// VULNERABLE: Code execution without sandboxing
async function executeUpdate(code: string) {
  try {
    // VULNERABLE: Direct evaluation of downloaded code
    const result = eval(code);
    
    return {
      success: true,
      result: result
    };
    
  } catch (error) {
    // VULNERABLE: Even errors might leak information
    throw new Error(`Update execution failed: ${error.message}`);
  }
}

// VULNERABLE: CI/CD webhook endpoint
export async function PUT(request: NextRequest) {
  try {
    const { buildConfig, deploymentKey, scripts } = await request.json();
    
    if (!buildConfig || !deploymentKey) {
      return NextResponse.json({ error: 'Build config and deployment key required' }, { status: 400 });
    }
    
    // VULNERABLE: Weak deployment key validation
    if (deploymentKey.length < 10) {
      return NextResponse.json({ error: 'Invalid deployment key' }, { status: 401 });
    }
    
    // VULNERABLE: Execute build scripts from request
    const buildResult = await executeBuildPipeline(buildConfig, scripts);
    
    return NextResponse.json({
      message: 'Deployment completed',
      buildResult: buildResult
    });
    
  } catch (error: any) {
    return NextResponse.json({
      error: 'Deployment failed',
      message: error.message
    }, { status: 500 });
  }
}

// VULNERABLE: Build pipeline with script injection
async function executeBuildPipeline(config: any, scripts: any[]) {
  const { exec } = require('child_process');
  const results = [];
  
  // VULNERABLE: Execute user-provided scripts
  for (const script of scripts || []) {
    const command = generateBuildCommand(config, script);
    
    const result = await new Promise((resolve, reject) => {
      // VULNERABLE: Command injection in build process
      exec(command, (error: any, stdout: string, stderr: string) => {
        resolve({ command, stdout, stderr, error: error?.message });
      });
    });
    
    results.push(result);
  }
  
  return results;
}

function generateBuildCommand(config: any, script: any): string {
  // VULNERABLE: String concatenation with user input
  let command = 'npm run build';
  
  if (config.environment) {
    command += ` --env=${config.environment}`; // Injection point
  }
  
  if (script.name) {
    command += ` && npm run ${script.name}`; // Command injection
  }
  
  if (script.args) {
    command += ` -- ${script.args.join(' ')}`; // Argument injection
  }
  
  return command;
}
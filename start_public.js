#!/usr/bin/env node

/**
 * 自动部署脚本（Ngrok API 版）
 * 功能：
 * 1. 杀死指定端口
 * 2. 启动 ngrok 并转发到本地服务
 * 3. 自动获取公网 URL（通过 ngrok API）
 * 4. 自动更新 GitHub OAuth App 的 Homepage / Callback URL
 * 5. 输出访问地址
 */

const { execSync, spawn } = require("child_process");
const axios = require("axios");
const dotenv = require("dotenv");

dotenv.config();

// ==== 配置 ====
const LOCAL_PORT = process.env.LOCAL_PORT || 8444;
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

// === 校验 ===
if (!GITHUB_CLIENT_ID || !GITHUB_TOKEN) {
  console.error("❌ 缺少 GITHUB_CLIENT_ID 或 GITHUB_TOKEN，请在 .env 文件中配置。");
  process.exit(1);
}

// 杀死端口
function killPort(port) {
  try {
    const pid = execSync(`lsof -ti:${port}`).toString().trim();
    if (pid) {
      console.log(`🔪 Killing process on port ${port} (PID: ${pid})...`);
      execSync(`kill -9 ${pid}`);
    }
  } catch {
    console.log(`✅ Port ${port} is free`);
  }
}

// 启动 ngrok 并通过 API 获取公网 URL
async function startNgrok() {
  console.log(`🚀 Starting ngrok for port ${LOCAL_PORT}...`);
  const ngrok = spawn("ngrok", ["http", `${LOCAL_PORT}`]);

  // 等待 ngrok 启动并创建隧道
  return new Promise((resolve, reject) => {
    setTimeout(async () => {
      try {
        const res = await axios.get("http://127.0.0.1:4040/api/tunnels");
        const tunnels = res.data.tunnels;
        if (tunnels.length > 0) {
          const publicUrl = tunnels[0].public_url;
          resolve(publicUrl);
        } else {
          reject("No tunnels found");
        }
      } catch (e) {
        reject("Failed to get ngrok URL. Maybe ngrok failed to start?");
      }
    }, 4000); // 等 4 秒让 ngrok 启动
  });
}

// 更新 GitHub OAuth App
async function updateGithubApp(publicUrl) {
  console.log(`🔧 Updating GitHub OAuth App URLs...`);
  const homepage = `${publicUrl}`;
  const callback = `${publicUrl}/api/auth/github/callback`;

  try {
    const res = await axios.patch(
      `https://api.github.com/applications/${GITHUB_CLIENT_ID}`,
      {
        homepage_url: homepage,
        callback_url: callback,
      },
      {
        headers: {
          Authorization: `token ${GITHUB_TOKEN}`,
          Accept: "application/vnd.github.v3+json",
        },
      }
    );
    console.log(`✅ Updated GitHub OAuth App`);
    console.log(`Homepage: ${homepage}`);
    console.log(`Callback: ${callback}`);
  } catch (err) {
    console.error("❌ Failed to update GitHub OAuth App:", err.response?.data || err.message);
  }
}

// 主流程
(async () => {
  killPort(3000);
  killPort(LOCAL_PORT);

  try {
    const publicUrl = await startNgrok();
    console.log(`🌍 Public URL: ${publicUrl}`);

    await updateGithubApp(publicUrl);

    console.log(`🎉 Done! Visit: ${publicUrl}/website.html`);
  } catch (err) {
    console.error("❌ Error:", err);
  }
})();

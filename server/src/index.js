# 使用官方 Node.js 镜像作为基础镜像
FROM node:18

# 设置工作目录
WORKDIR /app

# 复制 package.json 和 package-lock.json（如果存在）
COPY package*.json ./

# 安装依赖
RUN npm install

# 复制项目所有文件
COPY . .

# 设置环境变量（如需）
ENV NODE_ENV=production

# 暴露端口（与 Railway 设置一致，推荐使用 3000 或 process.env.PORT）
EXPOSE 3000

# 启动命令
CMD [ "node", "server/src/index.js" ]
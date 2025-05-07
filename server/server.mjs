import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import multer from 'multer';
import path from 'path';
import sharp from 'sharp';
import { fileURLToPath } from 'url';
import { pool, testConnection, initializeDatabase } from './src/utils/dbConfig.mjs';
import pingRoute from './routes/ping.mjs';
import authRoute from './routes/auth.mjs';  // 注意扩展名改为.mjs
import fs from 'fs';
import { dirname } from 'path';

// 获取当前文件的目录路径
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 加载环境变量
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3003; // 从环境变量读取端口，若未定义则默认使用3003

// 中间件配置
app.use(cors({
  origin: '*', // 允许所有来源访问
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// 添加一个检测CORS的中间件
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});

// 请求体解析中间件
app.use(express.json({
  limit: '10mb',
  verify: (req, res, buf) => {
    try {
      JSON.parse(buf);
    } catch (e) {
      console.error('JSON 解析错误:', e);
      res.status(400).json({ 
        success: false, 
        message: '无效的 JSON 数据',
        error: e.message 
      });
      throw new Error('无效的 JSON 数据');
    }
  }
}));
app.use(express.urlencoded({ extended: true }));

// 确保uploads目录存在
const avatarUploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(avatarUploadDir)) {
  fs.mkdirSync(avatarUploadDir, { recursive: true });
}

// 配置静态文件服务
app.use(express.static(path.join(__dirname, '../dist')));
console.log('静态文件目录:', path.join(__dirname, '../dist'));

// 明确配置上传文件夹的访问
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));
console.log('配置上传文件访问路径: /uploads -> ', path.join(__dirname, 'public/uploads'));

// 添加测试静态文件访问的端点
app.get('/api/test-static', (req, res) => {
  const publicDir = path.join(__dirname, 'public');
  const uploadsDir = path.join(publicDir, 'uploads');
  
  // 确保目录存在
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
  }
  
  const files = {
    uploadsDir: fs.existsSync(uploadsDir) ? '存在' : '不存在',
    uploadsContent: fs.existsSync(uploadsDir) ? fs.readdirSync(uploadsDir) : [],
    publicDir: fs.existsSync(publicDir) ? '存在' : '不存在',
    publicContent: fs.existsSync(publicDir) ? fs.readdirSync(publicDir) : [],
    staticFileUrl: '/uploads/default-config.png' // 测试这个静态文件是否可访问
  };
  
  res.json({
    success: true,
    message: '静态文件服务测试',
    data: files
  });
});

// 配置multer用于处理文件上传
const storage = multer.memoryStorage();

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 限制5MB
  fileFilter: function (req, file, cb) {
    // 检查文件类型
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('只允许上传图片文件！'));
    }
  }
});

// 挂载路由
app.use('/api', pingRoute);  // 挂载 ping 路由到 /api 前缀
app.use('/api/auth', authRoute);

// 添加测试数据库连接端点
app.get('/test-connection', async (req, res) => {
  try {
    const isConnected = await testConnection();
    res.json({ 
      success: true, 
      connected: isConnected,
      timestamp: new Date().toISOString(),
      message: isConnected ? '数据库连接成功' : '数据库连接失败'
    });
  } catch (error) {
    console.error('测试数据库连接失败:', error);
    res.status(500).json({ 
      success: false, 
      connected: false,
      message: '数据库连接失败',
      error: error.message
    });
  }
});

// JWT 验证中间件
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  console.log('收到需要认证的请求，Authorization头:', authHeader ? `${authHeader.substring(0, 15)}...` : 'undefined');

  if (!token) {
    console.log('未提供token，拒绝请求');
    return res.status(401).json({ 
      success: false,
      message: '未提供认证令牌' 
    });
  }

  const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
  console.log('使用JWT密钥验证, 密钥长度:', JWT_SECRET.length);

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('验证令牌失败, 错误类型:', err.name);
      console.error('错误详情:', err.message);
      
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          success: false,
          message: '令牌已过期，请重新登录',
          error: 'jwt expired'
        });
      } else if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({ 
          success: false,
          message: '无效的令牌格式',
          error: err.message
        });
      }
      
      return res.status(401).json({ 
        success: false,
        message: '无效的令牌',
        error: err.message
      });
    }
    
    // 确保用户ID存在并添加到请求对象中
    if (!decoded.userId) {
      console.error('令牌缺少userId字段:', decoded);
      return res.status(401).json({ 
        success: false,
        message: '无效的令牌格式' 
      });
    }
    
    console.log('验证令牌成功，用户ID:', decoded.userId);
    req.user = decoded;
    next();
  });
};

// 获取所有标签
app.get('/api/tags', async (req, res) => {
  try {
    // 导入标签服务模块
    const { getAllTags } = await import('./src/services/tagService.js');
    
    const tags = await getAllTags();
    
    res.json({
      success: true,
      data: tags
    });
  } catch (error) {
    console.error('获取所有标签失败:', error);
    res.status(500).json({
      success: false,
      message: '获取标签失败',
      error: error.message
    });
  }
});

// 获取热门标签
app.get('/api/tags/popular', async (req, res) => {
  let connection;
  try {
    const limit = parseInt(req.query.limit) || 20;
    console.log('获取热门标签, 限制数量:', limit);
    
    connection = await pool.getConnection();
    
    // 直接从数据库获取标签
    const [tags] = await connection.execute(`
      SELECT t.id, t.tag_name, COUNT(it.idea_id) as idea_count
      FROM buxing_platform.tags t
      LEFT JOIN buxing_platform.idea_tags it ON t.id = it.tag_id
      GROUP BY t.id
      ORDER BY idea_count DESC, t.tag_name
      LIMIT ?
    `, [limit]);
    
    console.log('获取到热门标签数量:', tags.length);
    
    // 如果没有标签，返回一些默认标签
    if (tags.length === 0) {
      const defaultTags = [
        { id: 1, tag_name: '设计', idea_count: 10 },
        { id: 2, tag_name: '技术', idea_count: 8 },
        { id: 3, tag_name: '创意', idea_count: 7 },
        { id: 4, tag_name: '商业', idea_count: 6 },
        { id: 5, tag_name: '项目', idea_count: 5 },
        { id: 6, tag_name: '营销', idea_count: 4 },
        { id: 7, tag_name: '应用', idea_count: 3 },
        { id: 8, tag_name: '教育', idea_count: 2 },
        { id: 9, tag_name: '金融', idea_count: 1 }
      ];
      
      res.json(defaultTags);
    } else {
      // 直接返回标签数组
      res.json(tags);
    }
  } catch (error) {
    console.error('获取热门标签失败:', error);
    
    // 错误时返回默认标签，确保前端不会崩溃
    const fallbackTags = [
      { id: 1, tag_name: '设计', idea_count: 5 },
      { id: 2, tag_name: '技术', idea_count: 4 },
      { id: 3, tag_name: '创意', idea_count: 3 }
    ];
    
    res.json(fallbackTags);
  } finally {
    if (connection) connection.release();
  }
});

// 搜索标签
app.get('/api/tags/search', async (req, res) => {
  try {
    const query = req.query.q || '';
    const limit = parseInt(req.query.limit) || 20;
    
    if (!query.trim()) {
      return res.json({
        success: true,
        data: []
      });
    }
    
    // 导入标签服务模块
    const { searchTags } = await import('./src/services/tagService.js');
    
    const tags = await searchTags(query, limit);
    
    res.json({
      success: true,
      data: tags
    });
  } catch (error) {
    console.error('搜索标签失败:', error);
    res.status(500).json({
      success: false,
      message: '搜索标签失败',
      error: error.message
    });
  }
});

// 创建新标签
app.post('/api/tags', async (req, res) => {
  try {
    const { tag_name } = req.body;
    
    if (!tag_name || typeof tag_name !== 'string' || !tag_name.trim()) {
      return res.status(400).json({
        success: false,
        message: '标签名称不能为空'
      });
    }
    
    // 导入标签服务模块
    const { cleanTagName } = await import('./src/services/tagService.js');
    
    // 清理标签名称
    const cleanedTagName = cleanTagName(tag_name);
    
    if (!cleanedTagName) {
      return res.status(400).json({
        success: false,
        message: '清理后的标签名称不能为空'
      });
    }
    
    // 检查标签是否已存在
    const [existingTags] = await pool.execute(
      'SELECT id, tag_name FROM buxing_platform.tags WHERE tag_name = ?',
      [cleanedTagName]
    );
    
    if (existingTags.length > 0) {
      // 返回已存在的标签
      return res.json({
        success: true,
        message: '标签已存在',
        data: existingTags[0]
      });
    }
    
    // 创建新标签
    const [result] = await pool.execute(
      'INSERT INTO buxing_platform.tags (tag_name) VALUES (?)',
      [cleanedTagName]
    );
    
    const newTagId = result.insertId;
    
    res.json({
      success: true,
      message: '标签创建成功',
      data: {
        id: newTagId,
        tag_name: cleanedTagName
      }
    });
  } catch (error) {
    console.error('创建标签失败:', error);
    res.status(500).json({
      success: false,
      message: '创建标签失败',
      error: error.message
    });
  }
});

// 获取创意的标签
app.get('/api/ideas/:ideaId/tags', async (req, res) => {
  try {
    const { ideaId } = req.params;
    
    const [tags] = await pool.execute(
      `SELECT t.id, t.tag_name 
       FROM buxing_platform.tags t
       JOIN buxing_platform.idea_tags it ON t.id = it.tag_id
       WHERE it.idea_id = ?
       ORDER BY t.tag_name`,
      [ideaId]
    );
    
    res.json({
      success: true,
      data: tags.map(tag => tag.tag_name)
    });
  } catch (error) {
    console.error(`获取创意(ID:${req.params.ideaId})标签失败:`, error);
    res.status(500).json({
      success: false,
      message: '获取创意标签失败',
      error: error.message
    });
  }
});

// 设置创意的标签
app.post('/api/ideas/:ideaId/tags', authenticateToken, async (req, res) => {
  try {
    const { ideaId } = req.params;
    const { tags } = req.body;
    const userId = req.user.id;
    
    console.log(`尝试更新创意(ID:${ideaId})标签: ${tags.join(', ')}`);
    
    if (!ideaId) {
      return res.status(400).json({
        success: false,
        message: '创意ID不能为空'
      });
    }
    
    if (!Array.isArray(tags)) {
      return res.status(400).json({
        success: false,
        message: '标签必须是数组格式'
      });
    }
    
    // 检查创意是否存在，以及当前用户是否有权限修改
    const [ideas] = await pool.execute(
      'SELECT id, user_id FROM buxing_platform.idea_card WHERE id = ?',
      [ideaId]
    );
    
    if (ideas.length === 0) {
      return res.status(404).json({
        success: false,
        message: '创意不存在'
      });
    }
    
    const idea = ideas[0];
    
    // 检查用户权限（仅创意所有者或管理员可以修改）
    if (idea.user_id !== userId && req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: '您没有权限修改此创意的标签'
      });
    }
    
    // 导入标签服务模块
    const { cleanTagName, deleteIdeaTags, setIdeaTags } = await import('./src/services/tagService.js');
    
    // 清理标签数据
    const cleanedTags = tags
      .map(tag => cleanTagName(tag))
      .filter(tag => tag.length > 0);
    
    // 删除现有标签关联
    await deleteIdeaTags(ideaId);
    
    // 处理新标签
    const results = await Promise.all(cleanedTags.map(async (tagName) => {
      // 检查标签是否已存在
      const [existingTags] = await pool.execute(
        'SELECT id FROM buxing_platform.tags WHERE tag_name = ?',
        [tagName]
      );
      
      let tagId;
      
      if (existingTags.length > 0) {
        // 使用现有标签
        tagId = existingTags[0].id;
      } else {
        // 创建新标签
        const [result] = await pool.execute(
          'INSERT INTO buxing_platform.tags (tag_name) VALUES (?)',
          [tagName]
        );
        tagId = result.insertId;
      }
      
      // 关联标签到创意
      try {
        await pool.execute(
          'INSERT INTO buxing_platform.idea_tags (idea_id, tag_id) VALUES (?, ?)',
          [ideaId, tagId]
        );
        return { success: true, tagName, tagId };
      } catch (error) {
        // 忽略唯一键冲突
        if (error.code === 'ER_DUP_ENTRY') {
          return { success: true, tagName, tagId, duplicate: true };
        }
        throw error;
      }
    }));
    
    // 更新创意的tags字段为规范化的JSON字符串
    await pool.execute(
      'UPDATE buxing_platform.idea_card SET tags = ? WHERE id = ?',
      [JSON.stringify(cleanedTags), ideaId]
    );
    
    console.log(`标签关联结果:`, results);
    
    res.json({
      success: true,
      message: '标签更新成功',
      data: {
        ideaId,
        tags: cleanedTags,
        results
      }
    });
  } catch (error) {
    console.error(`更新创意(ID:${req.params.ideaId})标签失败:`, error);
    res.status(500).json({
      success: false,
      message: '更新创意标签失败',
      error: error.message
    });
  }
});

// 创建想法卡片
app.post('/api/ideas', authenticateToken, async (req, res) => {
  let { 
    title, 
    description, 
    coverUrl = null, 
    price = 0, 
    detailedAnalysis = '', 
    tags = [], 
    allowComments = true, 
    showSimilar = true,
    status = 'published'
  } = req.body;
  
  const userId = req.user.userId;

  // 验证必需字段
  if (!title || !description) {
    return res.status(400).json({ 
      success: false,
      message: '标题和描述为必填项' 
    });
  }

  try {
    // 确保 tags 是一个数组
    if (typeof tags === 'string') {
      // 如果传入的是字符串，尝试解析为JSON
      try {
        tags = JSON.parse(tags);
      } catch (e) {
        // 如果解析失败，尝试以逗号分隔符分割字符串
        tags = tags.split(',').map(tag => tag.trim()).filter(Boolean);
      }
    } else if (!Array.isArray(tags)) {
      // 如果不是数组也不是字符串，初始化为空数组
      tags = [];
    }
    
    // 过滤掉空字符串和只有空格的标签
    tags = tags.filter(tag => tag && typeof tag === 'string' && tag.trim().length > 0);
    
    // 记录处理后的标签数据
    console.log('处理后的标签数据:', tags);

    const [result] = await pool.execute(
      `INSERT INTO buxing_platform.idea_card (
        user_id, title, description, cover_url, price, 
        detailed_analysis, tags, allow_comments, show_similar, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        userId, 
        title, 
        description, 
        coverUrl, 
        price, 
        detailedAnalysis, 
        JSON.stringify(tags), 
        allowComments ? 1 : 0, 
        showSimilar ? 1 : 0,
        status
      ]
    );

    const ideaId = result.insertId;
    console.log('创建想法成功:', result);
    
    // 关联标签到idea_tags表
    if (tags.length > 0) {
      try {
        // 导入tagService模块
        const { setIdeaTags } = await import('../src/services/tagService.js');
        await setIdeaTags(ideaId, tags);
        console.log('成功关联标签到idea_tags表');
      } catch (tagError) {
        console.error('关联标签失败:', tagError);
        // 即使标签关联失败也不影响创意的创建，仍返回成功
      }
    }

    res.status(201).json({
      success: true,
      message: '想法创建成功',
      data: {
        id: ideaId,
        title,
        description,
        tags // 返回处理后的标签数组
      }
    });
  } catch (error) {
    console.error('创建想法失败:', error);
    res.status(500).json({ 
      success: false,
      message: '创建想法过程中发生错误',
      error: error.message 
    });
  }
});

// 获取用户的想法列表
app.get('/api/ideas', authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    const [ideas] = await pool.execute(
      'SELECT * FROM buxing_platform.idea_card WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );

    res.json({
      message: '获取想法列表成功',
      ideas: ideas.map(idea => ({
        ...idea,
        tags: JSON.parse(idea.tags || '[]')
      }))
    });
  } catch (error) {
    console.error('获取想法列表失败:', error);
    res.status(500).json({ message: '获取想法列表过程中发生错误' });
  }
});

// 获取指定状态的创意列表
app.get('/api/ideas/all', async (req, res) => {
  try {
    console.log('收到/api/ideas/all请求');
    
    // 从idea_card表中获取所有创意，并附加创建者信息
    const [ideas] = await pool.execute(
      `SELECT i.*, u.nickname as creator_nickname, u.avatar as creator_avatar 
       FROM buxing_platform.idea_card i
       LEFT JOIN buxing_platform.users u ON i.user_id = u.id
       ORDER BY i.created_at DESC`
    );
    
    console.log(`查询到${ideas.length}条创意数据`);
    
    // 如果找到创意，返回它们
    res.json({
      success: true,
      message: '成功获取创意列表',
      data: ideas
    });
  } catch (error) {
    console.error('获取idea_card列表失败:', error);
    res.status(500).json({
      success: false,
      message: '获取创意列表失败',
      error: error.message
    });
  }
});

// 添加一个API别名，处理多级路径
app.get('/api/api/ideas/all', (req, res) => {
  // 重定向到正确的端点
  console.log('检测到重复的API路径，重定向到正确路径');
  req.url = '/api/ideas/all';
  app._router.handle(req, res);
});

// 获取我的创意 (可按状态过滤)
app.get('/api/ideas/my', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const status = req.query.status; // published, draft 或不指定获取全部
    
    console.log(`获取用户ID ${userId} 的创意，状态过滤:`, status);
    
    let query = 'SELECT * FROM buxing_platform.idea_card WHERE user_id = ?';
    let params = [userId];
    
    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }
    
    query += ' ORDER BY updated_at DESC';
    
    const [ideas] = await pool.execute(query, params);
    
    console.log(`获取到 ${ideas.length} 个创意`);
    
    res.json({
      success: true,
      data: ideas
    });
  } catch (error) {
    console.error('获取用户创意失败:', error);
    res.status(500).json({
      success: false,
      message: '获取用户创意失败',
      error: error.message
    });
  }
});

// 获取最近更新的创意
app.get('/api/ideas/recent', async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    console.log('正在获取最近更新的创意...');
    
    const query = `
      SELECT i.*, u.nickname as user_nickname 
      FROM buxing_platform.idea_card i
      LEFT JOIN buxing_platform.users u ON i.user_id = u.id
      WHERE i.status = 'published'
      ORDER BY i.updated_at DESC, i.created_at DESC
      LIMIT 20
    `;
    
    const [ideas] = await connection.execute(query);
    console.log('获取到最近创意数量:', ideas.length);
    
    // 处理标签数据
    const processedIdeas = ideas.map(idea => ({
      ...idea,
      tags: idea.tags ? JSON.parse(idea.tags) : [],
      allowComments: !!idea.allow_comments,
      showSimilar: !!idea.show_similar,
      price: idea.price || 0,
      thumbnail: idea.image_url || idea.thumbnail || null
    }));

    // 直接返回处理后的数据数组，而不是包裹在data属性里
    res.json(processedIdeas);
  } catch (error) {
    console.error('获取最近更新失败:', error);
    res.status(500).json({ 
      success: false, 
      message: '获取最近更新失败',
      error: error.message 
    });
  } finally {
    if (connection) connection.release();
  }
});

// 获取游客可见的创意
app.get('/api/ideas/guest', async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    console.log('正在获取游客可见创意...');
    
    const query = `
      SELECT i.*, u.nickname as publisher_nickname 
      FROM buxing_platform.idea_card i
      LEFT JOIN buxing_platform.users u ON i.user_id = u.id
      WHERE i.status = 'published' 
      ORDER BY i.created_at DESC 
      LIMIT 6
    `;
    
    const [ideas] = await connection.execute(query);
    console.log('获取到的游客创意数量:', ideas.length);
    
    // 处理标签数据
    const processedIdeas = ideas.map(idea => ({
      ...idea,
      tags: idea.tags ? JSON.parse(idea.tags) : [],
      allowComments: !!idea.allow_comments,
      showSimilar: !!idea.show_similar,
      publisherName: idea.publisher_nickname || '创意猎人'  // 使用昵称，如果没有则使用默认名称
    }));

    res.json({
      success: true,
      data: processedIdeas
    });
  } catch (error) {
    console.error('获取游客创意失败:', error);
    res.status(500).json({ 
      success: false, 
      message: '获取游客创意失败',
      error: error.message 
    });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});

// 获取默认图片
app.get('/api/images/default', async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    console.log('正在获取默认图片...');
    
    const [images] = await connection.execute(
      `SELECT * FROM buxing_platform.default_images 
       WHERE name = 'default_idea_image' AND is_active = 1`
    );
    
    if (images.length === 0) {
      return res.status(404).json({
        success: false,
        message: '未找到默认图片'
      });
    }
    
    const defaultImage = images[0];
    
    res.json({
      success: true,
      data: {
        id: defaultImage.id,
        name: defaultImage.name,
        description: defaultImage.description,
        imageUrl: defaultImage.image_url,
        imageData: defaultImage.image_data,
        type: defaultImage.type
      }
    });
  } catch (error) {
    console.error('获取默认图片失败:', error);
    res.status(500).json({
      success: false,
      message: '获取默认图片失败',
      error: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// 发送重置密码验证码
app.post('/api/auth/send-reset-code', async (req, res) => {
  let connection;
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: '请提供邮箱地址'
      });
    }

    connection = await pool.getConnection();
    
    // 检查邮箱是否存在
    const [existingUsers] = await connection.execute(
      'SELECT id FROM buxing_platform.users WHERE email = ?',
      [email]
    );

    if (existingUsers.length === 0) {
      return res.status(404).json({
        success: false,
        message: '该邮箱未注册'
      });
    }

    // 生成6位验证码
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    
    // 存储验证码和过期时间（15分钟后过期）
    const [result] = await connection.execute(
      'UPDATE buxing_platform.users SET reset_code = ?, reset_code_expires = DATE_ADD(NOW(), INTERVAL 15 MINUTE) WHERE email = ?',
      [resetCode, email]
    );

    // TODO: 发送验证码到邮箱
    console.log('验证码已发送到邮箱:', email, resetCode);

    res.json({
      success: true,
      message: '验证码已发送到您的邮箱'
    });
  } catch (error) {
    console.error('发送验证码错误:', error);
    res.status(500).json({
      success: false,
      message: '发送验证码失败，请稍后重试'
    });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});

// 重置密码
app.post('/api/auth/reset-password', async (req, res) => {
  let connection;
  try {
    const { email, code, newPassword } = req.body;
    
    if (!email || !code || !newPassword) {
      return res.status(400).json({
        success: false,
        message: '请提供完整信息'
      });
    }

    connection = await pool.getConnection();
    
    // 验证码检查
    const [users] = await connection.execute(
      'SELECT id FROM buxing_platform.users WHERE email = ? AND reset_code = ? AND reset_code_expires > NOW()',
      [email, code]
    );

    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        message: '验证码无效或已过期'
      });
    }

    // 更新密码
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const [result] = await connection.execute(
      'UPDATE buxing_platform.users SET password = ?, login_attempts = 0, locked_until = NULL, reset_code = NULL, reset_code_expires = NULL WHERE email = ?',
      [hashedPassword, email]
    );

    res.json({
      success: true,
      message: '密码重置成功'
    });
  } catch (error) {
    console.error('重置密码错误:', error);
    res.status(500).json({
      success: false,
      message: '重置密码失败，请稍后重试'
    });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});

// 获取当前用户已购买的创意
app.get('/api/ideas/purchases', authenticateToken, async (req, res) => {
  let connection;
  try {
    console.log('正在获取当前用户已购买创意...');
    connection = await pool.getConnection();
    const userId = req.user.userId;
    
    // 从购买记录表中获取用户购买的创意ID
    const query = `
      SELECT i.* 
      FROM buxing_platform.idea_purchase p
      JOIN buxing_platform.idea_card i ON p.idea_id = i.id
      WHERE p.user_id = ?
      ORDER BY p.created_at DESC
    `;
    
    const [ideas] = await connection.execute(query, [userId]);
    console.log('查询结果数量:', ideas.length);
    
    // 处理标签数据
    const processedIdeas = ideas.map(idea => ({
      ...idea,
      tags: idea.tags ? JSON.parse(idea.tags) : [],
      allowComments: !!idea.allow_comments,
      showSimilar: !!idea.show_similar
    }));
    
    res.json({
      success: true,
      data: processedIdeas
    });
  } catch (error) {
    console.error('获取用户已购买创意失败:', error);
    res.status(500).json({ 
      success: false, 
      message: '获取用户已购买创意失败',
      error: error.message 
    });
  } finally {
    if (connection) connection.release();
  }
});

// 专门用于图片上传的接口
app.post('/api/upload', upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({
      success: false,
      message: '未接收到图片文件'
    });
  }

  try {
    // 获取绝对路径
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    
    // 创建唯一文件名并保存处理后的图片
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(req.file.originalname || '.png');
    const filename = 'image-' + uniqueSuffix + ext;
    
    // 确保uploads目录存在
    const uploadsDir = path.join(__dirname, 'public/uploads');
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
      console.log(`创建上传目录: ${uploadsDir}`);
    }
    
    console.log('上传目录状态:', fs.statSync(uploadsDir));
    console.log('上传目录权限:', fs.accessSync(uploadsDir, fs.constants.W_OK | fs.constants.R_OK) ? 'No access' : 'Full access');
    
    const outputPath = path.join(uploadsDir, filename);
    
    // 直接保存文件到输出路径
    fs.writeFileSync(outputPath, req.file.buffer);
    console.log(`图片已保存到: ${outputPath}`);
        
    // 使用相对URL，不包含域名，确保URL格式正确且一致
    const url = `/uploads/${filename}`;
    console.log(`图片上传成功，生成URL: ${url}`);
    
    // 检查文件是否已写入
    if (fs.existsSync(outputPath)) {
      const stats = fs.statSync(outputPath);
      console.log(`已写入文件大小: ${stats.size} bytes`);
    } else {
      console.log('警告: 文件未成功写入');
    }
    
    // 打印服务器上传目录内容
    console.log('上传目录内容:', fs.readdirSync(uploadsDir));
    
    res.json({
      success: true,
      url: url,
      message: '图片上传成功'
    });
  } catch (error) {
    console.error('上传处理过程中出错:', error);
    res.status(500).json({
      success: false,
      message: '上传处理失败',
      error: error.message
    });
  }
});

// 获取创意详情
app.get('/api/ideas/:id', async (req, res) => {
  let connection;
  try {
    console.log('获取创意详情，ID:', req.params.id);
    connection = await pool.getConnection();
    
    // 修改查询，添加用户信息
    const [ideas] = await connection.execute(
      `SELECT i.*, u.nickname as author_nickname, u.email as author_username
       FROM buxing_platform.idea_card i
       LEFT JOIN buxing_platform.users u ON i.user_id = u.id
       WHERE i.id = ?`, 
      [req.params.id]
    );
    
    if (ideas.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: '创意不存在' 
      });
    }
    
    const idea = ideas[0];
    
    // 处理标签
    const processedIdea = {
      ...idea,
      tags: idea.tags ? JSON.parse(idea.tags) : [],
      allowComments: !!idea.allow_comments,
      showSimilar: !!idea.show_similar,
      author: {
        id: idea.user_id,
        nickname: idea.author_nickname || idea.author_username || `用户${idea.user_id}`
      }
    };
    
    res.json({
      success: true,
      data: processedIdea
    });
  } catch (error) {
    console.error('获取创意详情失败:', error);
    res.status(500).json({ 
      success: false, 
      message: '获取创意详情失败',
      error: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// 头像上传处理
app.post('/api/user/avatar', authenticateToken, upload.single('avatar'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: '未提供文件' });
  }

  const userId = req.user.userId;
  const file = req.file;
  
  try {
    // 创建文件夹（如果不存在）
    const avatarDir = path.join(avatarUploadDir, 'avatars');
    if (!fs.existsSync(avatarDir)) {
      fs.mkdirSync(avatarDir, { recursive: true });
    }
    
    // 生成唯一文件名
    const filename = `avatar-${userId}-${Date.now()}${path.extname(file.originalname)}`;
    const filepath = path.join(avatarDir, filename);
    
    // 处理图片
    await sharp(file.buffer)
      .resize(200, 200)
      .toFile(filepath);
      
    // 更新数据库中的头像URL
    const avatarUrl = `/uploads/avatars/${filename}`;
    
    let connection;
    try {
      connection = await pool.getConnection();
      
      // 首先检查avatar列是否存在
      const [columns] = await connection.execute(`
        SELECT COLUMN_NAME 
        FROM INFORMATION_SCHEMA.COLUMNS 
        WHERE TABLE_SCHEMA = 'buxing_platform' 
        AND TABLE_NAME = 'users' 
        AND COLUMN_NAME = 'avatar'
      `);
      
      if (columns.length === 0) {
        // 如果列不存在，尝试添加它
        try {
          await connection.execute(`
            ALTER TABLE buxing_platform.users 
            ADD COLUMN avatar VARCHAR(255)
          `);
          console.log('上传过程中添加avatar列成功');
        } catch (alterError) {
          console.error('上传过程中添加avatar列失败:', alterError);
          // 继续执行，因为ensureAvatarColumnExists函数可能已经添加了列
        }
      }
      
      // 更新用户头像
      await connection.execute(
        'UPDATE buxing_platform.users SET avatar = ? WHERE id = ?',
        [avatarUrl, userId]
      );
      
      console.log(`用户头像已更新，用户ID=${userId}, URL=${avatarUrl}`);
      
      res.json({
        success: true,
        message: '头像上传成功',
        avatarUrl: avatarUrl
      });
    } catch (dbError) {
      console.error('更新用户头像URL到数据库失败:', dbError);
      // 文件已上传成功，仅数据库更新失败，仍返回成功以保留上传的文件
      res.json({
        success: true,
        message: '头像上传成功，但数据库更新失败',
        avatarUrl: avatarUrl
      });
    } finally {
      if (connection) connection.release();
    }
  } catch (error) {
    console.error('处理头像上传失败:', error);
    res.status(500).json({
      success: false,
      message: '头像上传失败',
      error: error.message
    });
  }
});

// 获取用户信息
app.get('/api/user/info', authenticateToken, async (req, res) => {
  let connection;
  try {
    const userId = req.user.userId;
    console.log('正在获取用户信息，用户ID:', userId);
    
    connection = await pool.getConnection();
    const [users] = await connection.execute(
      'SELECT id, email, nickname, IFNULL(avatar, "") as avatar, created_at FROM buxing_platform.users WHERE id = ?',
      [userId]
    );
    
    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: '未找到用户'
      });
    }
    
    const user = users[0];
    
    // 返回用户信息
    res.json({
      success: true,
      message: '获取用户信息成功',
      data: {
        userId: user.id,
        email: user.email,
        nickname: user.nickname || '创意猎人',
        avatar: user.avatar || '/avatars/default1.png',
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('获取用户信息失败:', error);
    res.status(500).json({
      success: false,
      message: '获取用户信息失败',
      error: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// 更新用户个人资料
app.put('/api/user/profile', authenticateToken, async (req, res) => {
  let connection;
  try {
    const userId = req.user.userId;
    const { nickname, avatar } = req.body;
    
    console.log(`正在更新用户ID ${userId} 的个人资料，新昵称:`, nickname, '新头像:', avatar);
    
    if (!nickname || nickname.trim() === '') {
      return res.status(400).json({
        success: false,
        message: '昵称不能为空'
      });
    }
    
    connection = await pool.getConnection();
    
    // 更新用户昵称和头像
    const [result] = await connection.execute(
      'UPDATE buxing_platform.users SET nickname = ?, avatar = ? WHERE id = ?',
      [nickname, avatar, userId]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: '未找到用户或无变更'
      });
    }
    
    // 获取更新后的用户信息
    const [users] = await connection.execute(
      'SELECT id, email, nickname, IFNULL(avatar, "") as avatar, created_at FROM buxing_platform.users WHERE id = ?',
      [userId]
    );
    
    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: '获取更新后的用户信息失败'
      });
    }
    
    const user = users[0];
    
    // 返回更新后的用户信息
    res.json({
      success: true,
      message: '更新个人资料成功',
      data: {
        id: user.id,
        email: user.email,
        nickname: user.nickname,
        avatar: user.avatar || '/avatars/default1.png',
        createdAt: user.created_at
      }
    });
    
  } catch (error) {
    console.error('更新用户资料失败:', error);
    res.status(500).json({
      success: false,
      message: '更新用户资料失败',
      error: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// 获取指定用户信息
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  let connection;
  try {
    const targetId = req.params.id;
    console.log('正在获取用户信息（通过ID）:', targetId);
    connection = await pool.getConnection();
    const [users] = await connection.execute(
      'SELECT id, email, nickname, IFNULL(avatar, "") as avatar, created_at FROM buxing_platform.users WHERE id = ?',
      [targetId]
    );
    if (users.length === 0) {
      return res.status(404).json({ success: false, message: '未找到用户' });
    }
    const user = users[0];
    res.json({
      success: true,
      message: '获取用户信息成功',
      data: {
        userId: user.id,
        email: user.email,
        nickname: user.nickname,
        avatar: user.avatar,
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('获取指定用户信息失败:', error);
    res.status(500).json({ success: false, message: '获取用户信息失败', error: error.message });
  } finally {
    if (connection) connection.release();
  }
});

app.get("/", (req, res) => {
  res.send("捕星后端已启动！");
});

// 服务器错误处理中间件
app.use((err, req, res, next) => {
  console.error('服务器错误:', err);
  res.status(500).json({
    success: false,
    message: '服务器内部错误',
    error: err.message
  });
});

// 添加文件系统检查路径，用于调试
app.get('/api/debug/paths', (req, res) => {
  try {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    
    // 列出关键目录
    const serverPublic = path.join(__dirname, 'public');
    const serverUploads = path.join(__dirname, 'public/uploads');
    const defaultImagePath = '/Users/jayniu/Documents/项目文档/buxing idea.com/public/default-config.png';
    
    // 检查目录存在状态
    const pathsExist = {
      serverPublic: fs.existsSync(serverPublic),
      serverUploads: fs.existsSync(serverUploads),
      defaultImagePath: fs.existsSync(defaultImagePath)
    };
    
    // 如果uploads目录不存在，创建它
    if (!pathsExist.serverUploads) {
      fs.mkdirSync(serverUploads, { recursive: true });
      pathsExist.serverUploads = fs.existsSync(serverUploads);
    }
    
    res.json({
      success: true,
      paths: {
        dirname: __dirname,
        serverPublic,
        serverUploads,
        defaultImagePath
      },
      exists: pathsExist
    });
  } catch (error) {
    console.error('Debug paths error:', error);
    res.status(500).json({
      success: false,
      message: '获取路径信息失败',
      error: error.message
    });
  }
});

// 添加手动复制默认图片的接口
app.get('/api/debug/copy-default-image', (req, res) => {
  try {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    
    // 源文件路径和目标路径
    const defaultImagePath = '/Users/jayniu/Documents/项目文档/buxing idea.com/public/default-config.png';
    const serverUploads = path.join(__dirname, 'public/uploads');
    const targetPath = path.join(serverUploads, 'default_idea_image.png');
    
    // 确保目录存在
    if (!fs.existsSync(serverUploads)) {
      fs.mkdirSync(serverUploads, { recursive: true });
    }
    
    // 检查源文件是否存在
    if (!fs.existsSync(defaultImagePath)) {
      return res.status(404).json({
        success: false,
        message: '默认图片不存在',
        path: defaultImagePath
      });
    }
    
    // 复制文件
    fs.copyFileSync(defaultImagePath, targetPath);
    
    // 更新数据库记录
    pool.getConnection()
      .then(connection => {
        connection.execute(`
          UPDATE buxing_platform.default_images
          SET image_url = '/uploads/default_idea_image.png'
          WHERE name = 'default_idea_image' AND type = 'idea'
        `)
        .then(() => {
          console.log('更新数据库中的默认图片URL成功');
          connection.release();
        })
        .catch(dbError => {
          console.error('更新数据库中的默认图片URL失败:', dbError);
          connection.release();
        });
      })
      .catch(connError => {
        console.error('获取数据库连接失败:', connError);
      });
    
    res.json({
      success: true,
      message: '默认图片已复制',
      source: defaultImagePath,
      target: targetPath,
      url: '/uploads/default_idea_image.png'
    });
  } catch (error) {
    console.error('复制默认图片失败:', error);
    res.status(500).json({
      success: false,
      message: '复制默认图片失败',
      error: error.message
    });
  }
});

// 添加一个直接图片上传保存接口，便于调试
app.post('/api/debug/upload', upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({
      success: false,
      message: '未接收到图片文件'
    });
  }

  try {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    
    // 创建唯一文件名
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(req.file.originalname || '.png');
    const filename = 'debug-' + uniqueSuffix + ext;
    
    // 确保目录存在
    const uploadsDir = path.join(__dirname, 'public/uploads');
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }
    
    const outputPath = path.join(uploadsDir, filename);
    
    // 直接保存文件而不进行处理
    fs.writeFileSync(outputPath, req.file.buffer);
    
    const url = `/uploads/${filename}`;
    console.log('调试图片保存成功:', outputPath, '访问URL:', url);
    
    res.json({
      success: true,
      message: '图片上传成功（调试模式）',
      url: url,
      path: outputPath
    });
  } catch (error) {
    console.error('调试上传失败:', error);
    res.status(500).json({
      success: false,
      message: '调试上传失败',
      error: error.message
    });
  }
});

// ==== Idea Expansion Endpoints ====

// 添加创意扩展内容
app.post('/api/ideas/:ideaId/expansions', authenticateToken, async (req, res) => {
  try {
    const { ideaId } = req.params;
    const { content } = req.body;
    const userId = req.user.userId;

    console.log(`尝试为创意ID ${ideaId} 添加扩展内容，用户ID: ${userId}，内容长度: ${content ? content.length : 0}`);

    // 验证必需字段
    if (!content) {
      console.log('扩展内容为空，请求被拒绝');
      return res.status(400).json({ 
        success: false,
        message: '扩展内容不能为空' 
      });
    }

    // 先验证当前用户是否是该创意的发布者
    const [ideaRows] = await pool.execute(
      'SELECT user_id FROM buxing_platform.idea_card WHERE id = ?', 
      [ideaId]
    );

    if (ideaRows.length === 0) {
      console.log(`创意ID ${ideaId} 不存在`);
      return res.status(404).json({
        success: false,
        message: '创意不存在'
      });
    }

    console.log(`创意ID ${ideaId} 的发布者ID: ${ideaRows[0].user_id}, 当前用户ID: ${userId}`);

    // 检查用户是否是创意发布者
    if (parseInt(ideaRows[0].user_id) !== parseInt(userId)) {
      console.log(`用户ID ${userId} 不是创意ID ${ideaId} 的发布者，请求被拒绝`);
      return res.status(403).json({
        success: false,
        message: '只有创意发布者才能添加扩展内容'
      });
    }

    // 添加扩展内容
    const [result] = await pool.execute(
      `INSERT INTO buxing_platform.idea_expansions (idea_id, content) VALUES (?, ?)`,
      [ideaId, content]
    );

    console.log('成功添加扩展内容:', result);

    // 返回新创建的扩展内容信息
    const [newExpansion] = await pool.execute(
      `SELECT id, idea_id, content, published_at FROM buxing_platform.idea_expansions WHERE id = ?`,
      [result.insertId]
    );

    res.status(201).json({
      success: true,
      message: '成功添加扩展内容',
      data: newExpansion[0]
    });
  } catch (error) {
    console.error('添加扩展内容失败:', error);
    console.error('错误详情:', error.stack);
    res.status(500).json({
      success: false,
      message: '添加扩展内容失败',
      error: error.message
    });
  }
});

// 获取创意的扩展内容列表
app.get('/api/ideas/:ideaId/expansions', async (req, res) => {
  try {
    const { ideaId } = req.params;

    // 获取所有扩展内容
    const [expansions] = await pool.execute(
      `SELECT id, idea_id, content, published_at FROM buxing_platform.idea_expansions 
       WHERE idea_id = ? ORDER BY published_at ASC`,
      [ideaId]
    );

    console.log(`获取到创意ID ${ideaId} 的扩展内容数量:`, expansions.length);

    res.json({
      success: true,
      data: expansions
    });
  } catch (error) {
    console.error('获取扩展内容失败:', error);
    res.status(500).json({
      success: false,
      message: '获取扩展内容失败',
      error: error.message
    });
  }
});

// ==== End of Idea Expansion Endpoints ====

// ==== Favorites Endpoints ====

// 添加收藏
app.post('/api/ideas/:ideaId/favorite', authenticateToken, async (req, res) => {
  let connection;
  try {
    const { ideaId } = req.params;
    const userId = req.user.userId;
    
    console.log(`添加收藏，创意ID: ${ideaId}, 用户ID: ${userId}`);
    
    connection = await pool.getConnection();
    await connection.beginTransaction();
    
    // 检查是否已存在
    const [existing] = await connection.execute(
      'SELECT id FROM buxing_platform.favorites WHERE user_id = ? AND idea_id = ?',
      [userId, ideaId]
    );
    
    if (existing.length > 0) {
      await connection.commit();
      return res.json({
        success: true,
        message: '已经收藏过该创意',
        isFavorited: true,
        data: {
          ideaId: parseInt(ideaId),
          userId: parseInt(userId),
          isFavorited: true,
          favoriteId: existing[0].id,
          timestamp: new Date().toISOString()
        }
      });
    }
    
    // 添加收藏
    const [result] = await connection.execute(
      'INSERT INTO buxing_platform.favorites (user_id, idea_id) VALUES (?, ?)',
      [userId, ideaId]
    );
    
    await connection.commit();
    
    res.status(201).json({
      success: true,
      message: '收藏成功',
      isFavorited: true,
      data: {
        ideaId: parseInt(ideaId),
        userId: parseInt(userId),
        isFavorited: true,
        favoriteId: result.insertId,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('添加收藏失败:', error);
    if (connection) await connection.rollback();
    res.status(500).json({
      success: false,
      message: '添加收藏失败',
      error: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// 取消收藏
app.delete('/api/ideas/:ideaId/favorite', authenticateToken, async (req, res) => {
  let connection;
  try {
    const { ideaId } = req.params;
    const userId = req.user.userId;
    
    // 确保ideaId是干净的数字
    const cleanIdeaId = String(ideaId).split('_')[0].split(':')[0].trim();
    
    console.log(`正在取消收藏，创意ID: ${cleanIdeaId}, 用户ID: ${userId}`);
    
    connection = await pool.getConnection();
    await connection.beginTransaction();
    
    // 检查是否存在收藏记录
    const [existing] = await connection.execute(
      'SELECT id FROM buxing_platform.favorites WHERE user_id = ? AND idea_id = ?',
      [userId, cleanIdeaId]
    );
    
    if (existing.length === 0) {
      await connection.rollback();
      return res.json({
        success: true,
        message: '未找到收藏记录，可能已被删除',
        isFavorited: false,
        data: {
          ideaId: parseInt(cleanIdeaId),
          userId: parseInt(userId),
          isFavorited: false,
          timestamp: new Date().toISOString()
        }
      });
    }
    
    // 从收藏中删除
    const [result] = await connection.execute(
      'DELETE FROM buxing_platform.favorites WHERE user_id = ? AND idea_id = ?',
      [userId, cleanIdeaId]
    );
    
    // 获取更新后的收藏状态
    const [favorites] = await connection.execute(
      'SELECT id FROM buxing_platform.favorites WHERE user_id = ? AND idea_id = ?',
      [userId, cleanIdeaId]
    );
    
    const isFavorited = favorites.length > 0;
    
    await connection.commit();
    
    // 返回完整的响应，包括收藏状态
    res.json({
      success: true,
      message: '取消收藏成功',
      isFavorited: false, // 明确告知客户端取消收藏成功
      data: {
        ideaId: parseInt(cleanIdeaId),
        userId: parseInt(userId),
        isFavorited,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('取消收藏失败:', error);
    if (connection) {
      await connection.rollback();
    }
    res.status(500).json({
      success: false,
      message: '取消收藏失败: ' + error.message,
      error: error.message,
      isFavorited: true // 如果操作失败，假设收藏状态未变化
    });
  } finally {
    if (connection) connection.release();
  }
});

// 兼容旧路径的取消收藏请求
app.delete('/api/api/ideas/:ideaId/favorite', authenticateToken, async (req, res) => {
  console.log('检测到使用旧路径取消收藏，转发到正确路径');
  // 提取正确的ideaId
  const cleanIdeaId = String(req.params.ideaId).split('_')[0].split(':')[0].trim();
  // 创建新请求路径
  req.url = `/api/ideas/${cleanIdeaId}/favorite`;
  app._router.handle(req, res);
});

// 兼容带有:1等后缀的取消收藏请求
app.delete('/api/ideas/:ideaId/favorite:suffix', authenticateToken, async (req, res) => {
  console.log('检测到带有后缀的取消收藏请求:', req.params);
  // 提取正确的ideaId
  const cleanIdeaId = String(req.params.ideaId).split('_')[0].split(':')[0].trim();
  // 创建新请求路径
  req.url = `/api/ideas/${cleanIdeaId}/favorite`;
  app._router.handle(req, res);
});

// 检查是否已收藏
app.get('/api/ideas/:ideaId/favorite', authenticateToken, async (req, res) => {
  let connection;
  try {
    const { ideaId } = req.params;
    const userId = req.user.userId;
    
    console.log(`检查创意是否已收藏，创意ID: ${ideaId}, 用户ID: ${userId}`);
    
    connection = await pool.getConnection();
    
    // 检查是否已收藏
    const [favorites] = await connection.execute(
      'SELECT id FROM buxing_platform.favorites WHERE user_id = ? AND idea_id = ?',
      [userId, ideaId]
    );
    
    const isFavorited = favorites.length > 0;
    
    // 返回更详细的响应
    res.json({
      success: true,
      isFavorited, // 直接在顶层返回收藏状态
      data: {
        ideaId: parseInt(ideaId),
        userId: parseInt(userId),
        isFavorited,
        favoriteId: isFavorited ? favorites[0].id : null,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('检查收藏状态失败:', error);
    res.status(500).json({
      success: false,
      message: '检查收藏状态失败',
      error: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// 获取用户的所有收藏
app.get('/api/favorites', authenticateToken, async (req, res) => {
  let connection;
  try {
    const userId = req.user.userId;
    
    console.log('正在获取用户收藏列表，用户ID:', userId);
    
    connection = await pool.getConnection();
    
    // 获取用户的所有收藏及相关创意信息
    const [favorites] = await connection.execute(`
      SELECT 
        f.id, f.user_id, f.idea_id, f.created_at,
        i.title, i.description, i.cover_url, i.tags, i.status,
        i.user_id as creator_id, i.created_at as idea_created_at,
        u.nickname as creator_nickname, u.avatar as creator_avatar
      FROM buxing_platform.favorites f
      JOIN buxing_platform.idea_card i ON f.idea_id = i.id
      JOIN buxing_platform.users u ON i.user_id = u.id
      WHERE f.user_id = ?
      ORDER BY f.created_at DESC
    `, [userId]);
    
    // 处理每个收藏项的数据格式
    const processedFavorites = favorites.map(favorite => {
      // 处理标签数据，确保是数组格式
      let tags = [];
      try {
        if (favorite.tags) {
          tags = typeof favorite.tags === 'string' ? JSON.parse(favorite.tags) : favorite.tags;
        }
      } catch (e) {
        console.warn('解析标签JSON失败:', e);
      }
      
      // 返回统一的数据结构
      return {
        id: favorite.id,                    // 收藏记录ID
        idea_id: favorite.idea_id,          // 创意ID
        title: favorite.title || '',        // 标题
        description: favorite.description || '', // 描述
        cover_url: favorite.cover_url || '', // 封面URL
        tags: Array.isArray(tags) ? tags : [], // 确保标签是数组
        creator_nickname: favorite.creator_nickname || '创意猎人', // 创建者昵称
        creator_avatar: favorite.creator_avatar || '', // 创建者头像
        created_at: favorite.created_at     // 收藏时间
      };
    });
    
    res.json({
      success: true,
      message: '获取收藏列表成功',
      data: processedFavorites
    });
  } catch (error) {
    console.error('获取收藏列表失败:', error);
    res.status(500).json({
      success: false,
      message: '获取收藏列表失败',
      error: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// ==== End of Favorites Endpoints ====

// ==== Search Endpoints ====

// 搜索创意
app.get('/api/search/ideas', async (req, res) => {
  let connection;
  try {
    const { query, limit = 20, offset = 0 } = req.query;
    
    if (!query || query.trim() === '') {
      return res.status(400).json({
        success: false,
        message: '搜索关键词不能为空'
      });
    }
    
    console.log('执行创意搜索，关键词:', query);
    connection = await pool.getConnection();
    
    // 简化搜索逻辑，只搜索标题和描述
    const searchQuery = `
      SELECT i.*, u.nickname as creator_nickname, u.avatar as creator_avatar 
      FROM buxing_platform.idea_card i
      LEFT JOIN buxing_platform.users u ON i.user_id = u.id
      WHERE i.status = 'published' AND (
        i.title LIKE ? OR 
        i.description LIKE ?
      )
      ORDER BY i.created_at DESC
      LIMIT ? OFFSET ?
    `;
    
    const searchTerm = `%${query}%`;
    // 确保limit和offset是数字类型
    const limitNum = parseInt(limit, 10) || 20;
    const offsetNum = parseInt(offset, 10) || 0;
    
    console.log('搜索参数:', [searchTerm, searchTerm, limitNum, offsetNum]);
    
    const [ideas] = await connection.execute(
      searchQuery,
      [searchTerm, searchTerm, limitNum, offsetNum]
    );
    
    console.log(`搜索结果数量: ${ideas.length}`);
    
    // 处理标签数据
    const processedIdeas = ideas.map(idea => {
      // 处理标签数据
      let tags = [];
      try {
        if (idea.tags) {
          tags = typeof idea.tags === 'string' ? JSON.parse(idea.tags) : idea.tags;
        }
      } catch (e) {
        console.warn('解析标签JSON失败:', e);
      }
      
      return {
        ...idea,
        tags: Array.isArray(tags) ? tags : [],
        allowComments: !!idea.allow_comments,
        showSimilar: !!idea.show_similar,
        creatorNickname: idea.creator_nickname || '创意猎人',
        creatorAvatar: idea.creator_avatar || ''
      };
    });
    
    res.json({
      success: true,
      message: '搜索成功',
      data: processedIdeas,
      meta: {
        query,
        total: processedIdeas.length,
        limit: limitNum,
        offset: offsetNum
      }
    });
  } catch (error) {
    console.error('搜索创意失败:', error);
    res.status(500).json({
      success: false,
      message: '搜索创意失败',
      error: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// ==== End of Search Endpoints ====

// 添加一个独立的idea_card路由来响应前端请求
app.get('/api/idea_card', async (req, res) => {
  try {
    console.log('收到/api/idea_card请求');
    
    // 从idea_card表中获取所有创意
    const [ideas] = await pool.execute(
      'SELECT * FROM buxing_platform.idea_card ORDER BY created_at DESC'
    );
    
    console.log(`查询到${ideas.length}条创意数据`);
    
    // 如果找到创意，返回它们
    res.json({
      success: true,
      message: '成功获取创意列表',
      data: ideas
    });
  } catch (error) {
    console.error('获取idea_card列表失败:', error);
    res.status(500).json({
      success: false,
      message: '获取创意列表失败',
      error: error.message
    });
  }
});

// 获取已发布的创意列表
app.get('/api/ideas/published', async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    console.log('正在获取已发布创意列表...');
    
    const query = `
      SELECT i.*, u.nickname as user_nickname 
      FROM buxing_platform.idea_card i
      LEFT JOIN buxing_platform.users u ON i.user_id = u.id
      WHERE i.status = 'published'
      ORDER BY i.updated_at DESC, i.created_at DESC
      LIMIT 50
    `;
    
    const [ideas] = await connection.execute(query);
    console.log('获取到已发布创意数量:', ideas.length);
    
    // 处理标签数据和封面图片
    const processedIdeas = ideas.map(idea => {
      // 处理封面图片，设置默认值
      const coverImage = idea.cover_url || idea.image_url || idea.thumbnail || '/uploads/default_idea_image.png';
      
      return {
        ...idea,
        tags: idea.tags ? JSON.parse(idea.tags) : [],
        allowComments: !!idea.allow_comments,
        showSimilar: !!idea.show_similar,
        price: idea.price || 0,
        cover_url: coverImage,
        image_url: coverImage,
        thumbnail: coverImage
      };
    });

    res.json(processedIdeas);
  } catch (error) {
    console.error('获取已发布创意失败:', error);
    res.status(500).json({ 
      success: false, 
      message: '获取已发布创意失败',
      error: error.message 
    });
  } finally {
    if (connection) connection.release();
  }
});

// 获取特定ID的创意卡片
app.get('/api/idea_card/:id', async (req, res) => {
  try {
    const { id } = req.params;
    console.log('获取特定创意，ID:', id);
    
    // 从idea_card表中获取特定ID的创意
    const [ideas] = await pool.execute(
      'SELECT * FROM buxing_platform.idea_card WHERE id = ?',
      [id]
    );
    
    console.log(`查询结果:`, ideas.length ? '找到创意' : '未找到创意');
    
    // 如果找到创意，返回它
    if (ideas.length > 0) {
      res.json({
        success: true,
        message: '成功获取创意',
        data: ideas[0]
      });
    } else {
      res.status(404).json({
        success: false,
        message: `未找到ID为${id}的创意`,
        data: null
      });
    }
  } catch (error) {
    console.error(`获取创意(ID:${req.params.id})失败:`, error);
    res.status(500).json({
      success: false,
      message: '获取创意失败',
      error: error.message
    });
  }
});

// 删除创意/草稿
app.delete('/api/ideas/:ideaId', authenticateToken, async (req, res) => {
  let connection;
  try {
    const { ideaId } = req.params;
    const userId = req.user.userId;
    
    console.log(`删除创意/草稿，ID: ${ideaId}, 用户ID: ${userId}`);
    
    connection = await pool.getConnection();
    await connection.beginTransaction();
    
    // 检查创意是否存在且属于当前用户
    const [ideas] = await connection.execute(
      'SELECT id, user_id, status FROM buxing_platform.idea_card WHERE id = ?',
      [ideaId]
    );
    
    if (ideas.length === 0) {
      await connection.rollback();
      return res.status(404).json({
        success: false,
        message: '创意不存在'
      });
    }
    
    const idea = ideas[0];
    
    // 检查是否为创意所有者
    if (parseInt(idea.user_id) !== parseInt(userId)) {
      await connection.rollback();
      return res.status(403).json({
        success: false,
        message: '您没有权限删除该创意'
      });
    }
    
    // 删除关联数据 (标签、扩展内容、收藏等)
    
    // 1. 删除标签关联
    await connection.execute(
      'DELETE FROM buxing_platform.idea_tags WHERE idea_id = ?',
      [ideaId]
    );
    
    // 2. 删除扩展内容
    await connection.execute(
      'DELETE FROM buxing_platform.idea_expansions WHERE idea_id = ?',
      [ideaId]
    );
    
    // 3. 删除收藏记录
    await connection.execute(
      'DELETE FROM buxing_platform.favorites WHERE idea_id = ?',
      [ideaId]
    );
    
    // 4. 最后删除创意本身
    const [result] = await connection.execute(
      'DELETE FROM buxing_platform.idea_card WHERE id = ?',
      [ideaId]
    );
    
    if (result.affectedRows === 0) {
      await connection.rollback();
      return res.status(500).json({
        success: false,
        message: '删除创意失败'
      });
    }
    
    await connection.commit();
    
    res.json({
      success: true,
      message: '创意已成功删除'
    });
  } catch (error) {
    console.error('删除创意失败:', error);
    if (connection) {
      await connection.rollback();
    }
    res.status(500).json({
      success: false,
      message: '删除创意失败',
      error: error.message
    });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});

// 发布草稿

// 所有路由定义完成后，添加 404 catch-all 中间件，以防未命中路由
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: '未找到请求的资源'
  });
});

// 在服务器启动之前，确保avatar列存在
async function ensureAvatarColumnExists() {
  let connection;
  try {
    connection = await pool.getConnection();
    // 检查avatar列是否存在
    const [columns] = await connection.execute(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = 'buxing_platform' 
      AND TABLE_NAME = 'users' 
      AND COLUMN_NAME = 'avatar'
    `);
    
    if (columns.length === 0) {
      console.log('直接添加avatar列到users表...');
      await connection.execute(`
        ALTER TABLE buxing_platform.users 
        ADD COLUMN avatar VARCHAR(255)
      `);
      console.log('直接添加avatar列成功');
    } else {
      console.log('avatar列已存在');
    }
    return true;
  } catch (error) {
    console.error('检查或添加avatar列失败:', error);
    return false;
  } finally {
    if (connection) {
      connection.release();
    }
  }
}

// 检查并创建favorites表
const checkAndCreateFavoritesTable = async () => {
  try {
    const [favoriteTables] = await pool.query(
      "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'buxing_platform' AND TABLE_NAME = 'favorites'"
    );
    
    if (favoriteTables.length === 0) {
      console.log('创建favorites表...');
      await pool.query(`
        CREATE TABLE IF NOT EXISTS buxing_platform.favorites (
          id INT AUTO_INCREMENT PRIMARY KEY,
          user_id INT NOT NULL,
          idea_id INT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          CONSTRAINT fk_favorites_user_id
          FOREIGN KEY (user_id) REFERENCES buxing_platform.users(id)
          ON DELETE CASCADE ON UPDATE CASCADE,
          CONSTRAINT fk_favorites_idea_id
          FOREIGN KEY (idea_id) REFERENCES buxing_platform.idea_card(id)
          ON DELETE CASCADE ON UPDATE CASCADE,
          UNIQUE KEY uk_user_idea (user_id, idea_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
      `);
      console.log('favorites表创建成功');
    } else {
      console.log('favorites表已存在，跳过创建');
    }
    return true;
  } catch (error) {
    console.error('检查或创建favorites表失败:', error);
    return false;
  }
};

// 添加一个API健康检查端点
app.get('/api/health', async (req, res) => {
  try {
    const dbStatus = await testConnection();
    
    const response = {
      success: true,
      status: 'ok',
      message: 'API服务正常',
      serverTime: new Date().toISOString(),
      database: dbStatus ? 'connected' : 'disconnected',
      version: '1.0.0'
    };
    
    res.json(response);
  } catch (error) {
    res.status(500).json({
      success: false,
      status: 'error',
      message: '健康检查失败',
      error: error.message
    });
  }
});

// 启动服务器
app.listen(PORT, () => {
  console.log(`✅ 服务器运行在 http://localhost:${PORT}`);
}); 
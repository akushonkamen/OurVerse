// MongoDB 初始化脚本
db = db.getSiblingDB('ourverse');

// 创建用户集合索引
db.users.createIndex({ "provider": 1, "providerId": 1 }, { unique: true });
db.users.createIndex({ "email": 1 }, { unique: true, sparse: true });

// 创建照片集合索引
db.photos.createIndex({ "userId": 1 });
db.photos.createIndex({ "createdAt": -1 });

// 创建地理位置索引（2dsphere 用于地理查询）
db.photos.createIndex({ "lat": 1, "lng": 1 });

// 创建评论集合索引
db.photos.createIndex({ "comments.createdAt": -1 });

// 插入测试用户（可选）
db.users.insertOne({
  username: "admin",
  email: "admin@ourverse.com",
  avatar: "https://example.com/avatar.jpg",
  provider: "local",
  providerId: "admin",
  createdAt: new Date()
});

print("OurVerse MongoDB 初始化完成");

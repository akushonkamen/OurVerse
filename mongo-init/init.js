// MongoDB 初始化脚本
db = db.getSiblingDB('ourverse');

// 创建用户集合索引
db.users.createIndex({ "username": 1 }, { unique: true });
db.users.createIndex({ "email": 1 }, { unique: true, sparse: true });

try {
  db.users.dropIndex("githubId_1");
} catch (error) {
  if (error.codeName !== 'IndexNotFound') {
    print('移除旧 githubId 索引失败:', error);
  }
}

db.users.createIndex(
  { "githubId": 1 },
  {
    unique: true,
    partialFilterExpression: {
      provider: 'github',
      githubId: { $type: 'string' }
    }
  }
);

db.users.createIndex({ "registrationDeviceId": 1 }, { unique: true, sparse: true });

// 创建照片集合索引
db.photos.createIndex({ "userId": 1, "createdAt": -1 });
db.photos.createIndex({ "location": "2dsphere" });
db.photos.createIndex({ "comments.createdAt": -1 });

// 插入测试用户（可选）
db.users.updateOne(
  { username: "admin" },
  {
    $setOnInsert: {
      email: "admin@ourverse.com",
      avatar: "https://example.com/avatar.jpg",
      provider: "local",
      createdAt: new Date()
    }
  },
  { upsert: true }
);

print("OurVerse MongoDB 初始化完成");

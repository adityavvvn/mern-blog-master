require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");
const User = require('./models/User');
const Post = require('./models/Post');
const bcrypt = require('bcryptjs');
const app = express();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const uploadMiddleware = multer({ dest: 'uploads/' });
const fs = require('fs');
const salt = bcrypt.genSaltSync(10);
const secret = process.env.JWT_SECRET;

app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(__dirname + '/uploads'));

mongoose.connect(process.env.MONGO_URL)
  .then(() => {
    console.log('✅ Connected to MongoDB');
  })
  .catch((err) => {
    console.error('❌ Failed to connect to MongoDB:', err.message);
  });

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.create({
      username,
      password: bcrypt.hashSync(password, salt),
    });
    res.json(userDoc);
  } catch (e) {
    console.log(e);
    res.status(400).json(e);
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.findOne({ username });
    if (!userDoc) return res.status(400).json('wrong credentials');

    const passOk = bcrypt.compareSync(password, userDoc.password);
    if (!passOk) return res.status(400).json('wrong credentials');

    jwt.sign({ username, id: userDoc._id }, secret, {}, (err, token) => {
      if (err) throw err;
      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // use HTTPS in prod
        sameSite: 'none', // allow cross-site cookies
      }).json({
        id: userDoc._id,
        username,
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json('Internal server error');
  }
});

app.get('/profile', (req, res) => {
  const { token } = req.cookies;
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, secret, {}, (err, info) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    res.json(info);
  });
});

app.post('/logout', (req, res) => {
  res.cookie('token', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'none',
  }).json('ok');
});

app.post('/post', uploadMiddleware.single('file'), async (req, res) => {
  const { token } = req.cookies;
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { originalname, path } = req.file;
    const parts = originalname.split('.');
    const ext = parts[parts.length - 1];
    const newPath = path + '.' + ext;
    fs.renameSync(path, newPath);

    const { title, summary, content } = req.body;
    try {
      const postDoc = await Post.create({
        title,
        summary,
        content,
        cover: newPath,
        author: info.id,
      });
      res.json(postDoc);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Failed to create post' });
    }
  });
});

app.put('/post', uploadMiddleware.single('file'), async (req, res) => {
  const { token } = req.cookies;
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });

    let newPath = null;
    if (req.file) {
      const { originalname, path } = req.file;
      const parts = originalname.split('.');
      const ext = parts[parts.length - 1];
      newPath = path + '.' + ext;
      fs.renameSync(path, newPath);
    }

    const { id, title, summary, content } = req.body;
    try {
      const postDoc = await Post.findById(id);
      if (!postDoc) return res.status(404).json('Post not found');

      const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
      if (!isAuthor) return res.status(403).json('You are not the author');

      await postDoc.updateOne({
        title,
        summary,
        content,
        cover: newPath ? newPath : postDoc.cover,
      });

      res.json(postDoc);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Failed to update post' });
    }
  });
});

app.get('/post', async (req, res) => {
  try {
    const posts = await Post.find()
      .populate('author', ['username'])
      .sort({ createdAt: -1 })
      .limit(20);
    res.json(posts);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to get posts' });
  }
});

app.get('/post/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const postDoc = await Post.findById(id).populate('author', ['username']);
    if (!postDoc) return res.status(404).json('Post not found');
    res.json(postDoc);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to get post' });
  }
});

app.delete('/post/:id', async (req, res) => {
  const { token } = req.cookies;
  const { id } = req.params;
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });

    try {
      const postDoc = await Post.findById(id);
      if (!postDoc) return res.status(404).json('Post not found');

      const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
      if (!isAuthor) return res.status(403).json('You are not the author');

      if (postDoc.cover && fs.existsSync(postDoc.cover)) {
        fs.unlinkSync(postDoc.cover);
      }

      await Post.findByIdAndDelete(id);
      res.json({ success: true });
    } catch (error) {
      console.error(error);
      res.status(500).json('Failed to delete post');
    }
  });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

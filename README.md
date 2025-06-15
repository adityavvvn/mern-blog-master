# MERN Blog Application

A full-stack blog application built with the MERN stack (MongoDB, Express.js, React.js, Node.js) that allows users to create, read, update, and delete blog posts.

## 🌐 Live Demo

- Frontend: [https://mern-blog-master-1-kx73.onrender.com](https://mern-blog-master-1-kx73.onrender.com)
- Backend API: [https://mern-blog-master-rn9z.onrender.com](https://mern-blog-master-rn9z.onrender.com)

## 🚀 Features

- User authentication (Sign up, Login, Logout)
- Create, read, update, and delete blog posts
- Responsive design for all devices
- Rich text editor for blog content
- Image upload functionality
- Comment system
- User profiles
- Search functionality

## 🛠️ Tech Stack

### Frontend
- React.js
- Redux Toolkit for state management
- React Router for navigation
- Axios for API requests
- Material-UI for styling
- React Quill for rich text editing

### Backend
- Node.js
- Express.js
- MongoDB for database
- Mongoose for ODM
- JWT for authentication
- Multer for file uploads
- Bcrypt for password hashing

## 📦 Project Structure

```
mern-blog-master/
├── client/                 # Frontend React application
│   ├── public/            # Static files
│   └── src/               # React source files
│       ├── components/    # Reusable components
│       ├── pages/         # Page components
│       ├── redux/         # Redux store and slices
│       └── utils/         # Utility functions
│
├── api/                   # Backend Node.js/Express application
│   ├── controllers/       # Route controllers
│   ├── models/           # Mongoose models
│   ├── routes/           # API routes
│   ├── middleware/       # Custom middleware
│   └── config/           # Configuration files
│
└── package.json          # Project dependencies and scripts
```

## 🚀 Getting Started

### Prerequisites

- Node.js (v14 or higher)
- MongoDB
- npm or yarn

### Installation

1. Clone the repository
```bash
git clone https://github.com/yourusername/mern-blog-master.git
cd mern-blog-master
```

2. Install dependencies for both frontend and backend
```bash
# Install backend dependencies
cd api
npm install

# Install frontend dependencies
cd ../client
npm install
```

3. Create a `.env` file in the api directory with the following variables:
```env
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
PORT=5000
```

4. Create a `.env` file in the client directory:
```env
REACT_APP_API_URL=http://localhost:5000
```

### Running the Application

1. Start the backend server:
```bash
cd api
npm start
```

2. Start the frontend development server:
```bash
cd client
npm start
```

The application will be available at:
- Frontend: http://localhost:3000
- Backend: http://localhost:5000

## 🔧 Environment Variables

### Backend (.env)
- `MONGODB_URI`: MongoDB connection string
- `JWT_SECRET`: Secret key for JWT token generation
- `PORT`: Backend server port (default: 5000)

### Frontend (.env)
- `REACT_APP_API_URL`: Backend API URL

## 📝 API Endpoints

### Authentication
- POST `/api/auth/register` - Register a new user
- POST `/api/auth/login` - Login user
- GET `/api/auth/logout` - Logout user

### Posts
- GET `/api/posts` - Get all posts
- GET `/api/posts/:id` - Get a single post
- POST `/api/posts` - Create a new post
- PUT `/api/posts/:id` - Update a post
- DELETE `/api/posts/:id` - Delete a post

### Comments
- GET `/api/posts/:id/comments` - Get comments for a post
- POST `/api/posts/:id/comments` - Add a comment to a post
- DELETE `/api/comments/:id` - Delete a comment

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- Your Name - Initial work

## 🙏 Acknowledgments

- Thanks to all contributors who have helped shape this project
- Special thanks to the MERN stack community for their excellent documentation and support 

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


const app = express();
app.use(express.json());


let users = [];
let profiles = [];

const jwtSecret = 'degiuaky_wfs';


const auth = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).send('Authentication required');

    try {
        const decoded = jwt.verify(token, jwtSecret);
        req.user = users.find(u => u.id === decoded.id);
        if (!req.user) return res.status(404).send('User not found');
        next();
    } catch (error) {
        res.status(401).send('Invalid token');
    }
};

// API tạo tài khoản
app.post('/api/users/create', async (req, res) => {
    const { userName, password, fullName, birthDate, place_of_birth, nationality } = req.body;
    try {
        // Kiểm tra người dùng đã tồn tại
        if (users.some(user => user.userName === userName)) {
            return res.status(400).send('Username already exists');
        }

        // Mã hóa mật khẩu
        const hashedPassword = await bcrypt.hash(password, 10);

        // Tạo profile mới
        const profileId = profiles.length + 1;
        const profile = { id: profileId, fullName, birthDate, place_of_birth, nationality };
        profiles.push(profile);

        // Tạo người dùng mới
        const user = { id: users.length + 1, userName, password: hashedPassword, profile_id: profileId };
        users.push(user);

        res.status(201).json({ message: 'User created successfully', user });
    } catch (error) {
        res.status(400).json({ message: 'Error creating user', error });
    }
});

// API đăng nhập
app.post('/api/users/login', async (req, res) => {
    const { userName, password } = req.body;
    try {
        const user = users.find(u => u.userName === userName);
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user.id }, jwtSecret, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: 'Error logging in', error });
    }
});

// API đăng xuất
app.post('/api/users/logout', auth, (req, res) => {
    res.send('Logged out successfully');
});

// API lấy hồ sơ 
app.get('/api/users/profile/:id', auth, (req, res) => {
    try {
        const profile = profiles.find(p => p.id == req.params.id);
        if (!profile) return res.status(404).json({ message: 'Profile not found' });

        res.json(profile);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching profile', error });
    }
});

// API cập nhật hồ sơ 
app.put('/api/users/profile/:id', auth, (req, res) => {
    try {
        const profile = profiles.find(p => p.id == req.params.id);
        if (!profile) return res.status(404).send('Profile not found');

        // Chỉ cho phép chủ sở hữu chỉnh sửa
        if (profile.id !== req.user.profile_id) {
            return res.status(403).send('Unauthorized to edit this profile');
        }

        const { fullName, birthDate, place_of_birth, nationality } = req.body;

        profile.fullName = fullName || profile.fullName;
        profile.birtDate = birthDate || profile.birthDate;
        profile.place_of_birth = place_of_birth || profile.place_of_birth;
        profile.nationality = nationality || profile.nationality;

        res.json({ message: 'Profile updated successfully', profile });
    } catch (error) {
        res.status(500).json({ message: 'Error updating profile', error });
    }
});

const PORT = 8080;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

import './form.css';
import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';

const Register = () => {
    const { register } = useAuth();
    const [error, setError] = useState("");
    const [data, setData] = useState({
        username: '',
        firstname: '',
        lastname: '',
        password: ''
    });

    const handle_change = (e) => {
        const { name, value } = e.target;
        setData({ ...data, [name]: value });
    };

    const handle_submit = (e) => {
        e.preventDefault();
        register(data)
        .then(message => setError(message));
    };

    return <>
        <h2>Registration</h2>
        <form onSubmit={handle_submit}>
            <label htmlFor="username">User Name:</label>
            <input
                type="text"
                id="username"
                name="username"
                placeholder='User Name'
                value={data.username}
                onChange={handle_change}
                required
            />
            <label htmlFor="firstname">First Name:</label>
            <input
                type="text"
                id="firstname"
                name="firstname"
                placeholder='First Name'
                value={data.firstname}
                onChange={handle_change}
                required
            />
            <label htmlFor="lastname">Last Name:</label>
            <input
                type="text"
                id="lastname"
                name="lastname"
                placeholder='Last Name'
                value={data.lastname}
                onChange={handle_change}
                required
            />
            <label htmlFor="password">Password:</label>
            <input
                type="password"
                id="password"
                name="password"
                placeholder='Password'
                value={data.password}
                onChange={handle_change}
                required
            />
            <div className="btn-container">
                <button type="submit">Register</button>
            </div>
            <p className="error">{error}</p>
        </form>
    </>;
};

export default Register;
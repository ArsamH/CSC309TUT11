import "./Layout.css";
import { Link, Outlet } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

const Layout = () => {
    const { user, logout } = useAuth();
    return <>
        <header>
            <Link to="/">Home</Link>
            { user ? <>
                <Link to="/profile" className="user">{user.username}</Link>
                <a href="#" onClick={logout}>Logout</a>
                </> :
                <Link to="/login">Login</Link>
            }
        </header>
        <main>
            <Outlet />
        </main>
        <footer>
            &copy; CSC309, Fall 2025, Tutorial 11 
        </footer>
    </>;
};

export default Layout;

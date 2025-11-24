import { useAuth } from "../contexts/AuthContext";
import "./main.css";

function Profile() {
    const { user, logout } = useAuth();
    const date = new Date(user?.createdAt);
    const options = { hour: 'numeric', minute: 'numeric', hour12: true };
    const pretty_date = date.toLocaleTimeString('en-US', options);

    return <>
        <h3>Hello, {user?.firstname} {user?.lastname}!</h3>
        <p>You have been with us since {pretty_date}.</p>
        <div className="row">
            <a href="#" onClick={logout}>Logout</a>
        </div>
    </>;
}

export default Profile;

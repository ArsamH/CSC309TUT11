import './Home.css';
import AddCity from '../components/AddCity';
import { useRef, useState } from "react";
import { useCities } from '../contexts/CitiesContext';
import City from '../components/City';

function Home({ setPage }) {
    const dialog_ref = useRef(null);
    const { cities } = useCities();
    const [error, setError] = useState("");
    
    const open_dialog = () => dialog_ref.current?.showModal();

    return <>
        <h1>Weather With You</h1>
        <div className="cities">
            {cities.map((city) => (
                <City key={city.id} city={city} setPage={setPage} />
            ))}
        </div>
        <button className="btn" onClick={open_dialog}>Add City</button>
        <AddCity ref={dialog_ref} setError={setError} />
        { error && <p className="error">{error}</p> }
    </>;
}

export default Home;
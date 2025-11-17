import './City.css';

const City = ({ city, setPage }) => {
    const temperature = null;

    // TODO: complete me
    // HINT: fetch the current temperature of the city from Open-Meteo

    const handle_click = () => {
        setPage(city.id);
    };

    return (
        <div className="city-card">
            <button className="remove-btn">×</button>
            <div className="city-content" onClick={handle_click}>
                <h2>{city.name}</h2>
                {temperature !== null ? (
                    <p className="temperature">{temperature}°C</p>
                ) : (
                    <div className="spinner"></div>
                )}
            </div>

        </div>
    );
};

export default City;
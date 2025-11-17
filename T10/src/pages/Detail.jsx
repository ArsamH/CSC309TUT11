import "./Detail.css";
import { useCities } from "../contexts/CitiesContext";
import NotFound from "./NotFound";

function Weather({ city, setPage }) {
    const weather = null;

    // TODO: complete me
    // HINT: fetch the city's weather information from Open-Meteo

    const handle_click = () => {
        setPage("home");
    };

    return <>
        <h1>{city.name}</h1>
        {weather ? <div className="weather-info">
            <div>
                <h3>Temperature</h3>
                <p>{weather.temperature_2m}°C</p>
            </div>
            <div>
                <h3>Humidity</h3>
                <p>{weather.relative_humidity_2m}%</p>
            </div>
            <div>
                <h3>Wind</h3>
                <p className="small">{weather.wind_speed_10m} km/h</p>
            </div>
            <div>
                <h3>Precipitation</h3>
                <p>{weather.precipitation_probability}%</p>
            </div>
        </div> : <div className="spinner"></div>}
        <button className="btn" onClick={handle_click}>Back</button>
    </>;
}

function Detail({ cityId, setPage }) {
    const { cities } = useCities();

    const city = cities.find((c) => c.id == cityId);
    if (!city) {
        return <NotFound />;
    }

    return <Weather city={city} setPage={setPage} />;
}

export default Detail;
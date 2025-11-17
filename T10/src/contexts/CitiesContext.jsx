import { createContext, useContext, useState } from "react";

const CitiesContext = createContext();

export const CitiesProvider = ({ children }) => {
    const [cities, _setCities] = useState([
        { id: 1, name: "Toronto", latitude: 43.70011, longitude: -79.4163 }
    ]);

    // TODO: complete me
    // HINT: it may be good to provide addCity and removeCity functions

    return (
        <CitiesContext.Provider value={{ cities, /* ADD MORE GLOBALS */ }}>
            {children}
        </CitiesContext.Provider>
    );
};

export const useCities = () => {
    return useContext(CitiesContext);
};

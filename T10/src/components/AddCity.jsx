import './AddCity.css';
import { forwardRef, useState } from "react";

const AddCity = forwardRef(({ setError }, ref) => {
    const [cityName, setCityName] = useState("");

    const handle_submit = (e) => {
        e.preventDefault(); 

        setError("TODO: complete me");    
        // HINT: fetch the coordinates of the city from Nominatim,
        //       then add it to CitiesContext's list of cities.
        
        setCityName("");
        ref.current?.close();
    };

    return (
        <dialog ref={ref}>
            <div className="dialog-header">
                <span>Add A City</span>
                <a onClick={() => ref.current?.close()}>✖</a>
            </div>

            <form onSubmit={handle_submit}>
                <input
                    type="text"
                    placeholder="Enter City Name"
                    value={cityName}
                    onChange={(e) => setCityName(e.target.value)}
                    required
                />
                
                <div className="button-group">
                    <button type="submit">Add</button>
                    <button type="button" onClick={() => ref.current?.close()}>
                        Close
                    </button>
                </div>
            </form>
        </dialog>
    );
});

export default AddCity;

import './App.css';
import { useState } from 'react';
import { CitiesProvider } from './contexts/CitiesContext';
import Layout from './components/Layout';
import Home from './pages/Home';
import NotFound from './pages/NotFound';
import Detail from './pages/Detail';

const App = () => {
    const [page, setPage] = useState("home");
    let component;

    if (page === "home") {
        component = <Home setPage={setPage} />;
    }
    else if (typeof(page) === "number") {
        component = <Detail cityId={page} setPage={setPage} />;
    }
    else {
        component = <NotFound />;
    }

    return <CitiesProvider>
        <Layout>
            {component}
        </Layout>
    </CitiesProvider>;
};

export default App;
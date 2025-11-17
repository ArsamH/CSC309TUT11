import './Layout.css';

const Layout = ({ children }) => {
    const get_academic_term = () => {
        const month = new Date().getMonth() + 1; // getMonth() is 0-indexed, so add 1
        const year = new Date().getFullYear();
        
        let season;
    
        if (month >= 1 && month <= 4) {
            season = "Winter";
        } else if (month >= 5 && month <= 8) {
            season = "Summer";
        } else {
            season = "Fall";
        }
    
        return `${season} ${year}`;
    };

    return <>
        <header>
            <a href="/" className="link">CSC309: Tutorial 10</a>
        </header>
        <main>
            {children}
        </main>
        <footer>
            &copy; CSC309, {get_academic_term()}, University of Toronto.
        </footer>
    </>;
};

export default Layout;


import  React from 'react';
import {Navbar,Nav} from 'react-bootstrap';
// Import routing components
 
import { BrowserRouter as Router,Route,Link} from 'react-router-dom';



class Header extends React.Component {
    render(){
        // eslint-disable-next-line 
        return(
            // eslint-disable-next-line 
            <div width="100%">
              <nav className="nav-container">
                <div className="alignment-left">  
                <ul className="navigation-menu">
                  <li >
                    <Link to="/">Home</Link>
                  </li>
                  <li>
                    <Link to="/API">API</Link>
                  </li>
                  <li>
                    <Link to="/signout">Contribute</Link>
                  </li>
                </ul>
                </div>
                <div className="alignment-center">  
                Covid-19 Safe Trace
                </div>
                <div className="alignment-right">  
                <ul >
                <li>
                    <Link to="/signin">Log-In</Link>
                </li>
                <li>
                    <Link to="/signout">Sign-Up</Link>
                </li>
                </ul>
                </div>
              </nav>
            
                {/* <Route exact path="/" component={home} />
                <Route exact path="/signin" component={signin} />
                <Route exact path="/signout" component={signout} />  */}
            
            </div>
          
		
		
           
         
        );
    }

}
export default Header
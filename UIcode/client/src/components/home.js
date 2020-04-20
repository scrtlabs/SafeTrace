import React from 'react';
import Header from './header'
import {Card,Button} from 'react-bootstrap';
class Home extends React.Component {
    render(){
        return(
           
            <div><Header /> 
            <div className="centeralign">
            <Card border="light" style={{ width: '18rem' }}>
           
            <Card.Body>
                <Card.Title>Yours privacy matters.Help to Combat COVID-19 safely and securely</Card.Title>
                <Card.Text>
                  Privately share your location history and compare it with other anonymous users
                </Card.Text>
                <Button variant="primary">I want to help</Button>
            </Card.Body>
            </Card>
            
            </div>
            
            </div>
           
        );
    }
}
export default Home
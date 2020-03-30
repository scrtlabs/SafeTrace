import React from 'react';
import Header from './header'
import {Card,Button} from 'react-bootstrap';
class API extends React.Component {
    render(){
        return(
<div><Header /> 
            <div>
            <Card border="light" >
           
            <Card.Body>
                <Card.Title>API Developers are coming Soon!</Card.Title>
                <Card.Text>
                 
                </Card.Text>
              
            </Card.Body>
            </Card>
            
            </div>
            
            </div>
        );
    }
}
export default API
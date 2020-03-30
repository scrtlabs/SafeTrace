import React, { Component } from 'react';
import Header from './header'
import {Card,Button} from 'react-bootstrap';
class signout extends React.Component {
    render(){
        return(
            <div><Header /> 
            <div className="centeralign">
            <Card border="light" style={{ width: '18rem' }}>
           
            <Card.Body>
                <Card.Title>You have successfully logged out!</Card.Title>
                <Card.Text>
                 
                </Card.Text>
                <Button variant="primary">Login Again !</Button>
            </Card.Body>
            </Card>
            
            </div>
            
            </div>
        );
    }
}
export default signout
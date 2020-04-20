import React from 'react';
import {Form,Button} from 'react-bootstrap';
import Header from './header'

class signin extends React.Component {
    render(){
        return(
         <div>
             <Header />
             <div className="loginBlock"> 
            <Form>
            <Form.Group controlId="formBasicEmail">
                
                <Form.Control type="email" placeholder="Enter email" />
                <Form.Text className="text-muted">
                We'll never share your email with anyone else.
                </Form.Text>
            </Form.Group>

            <Form.Group controlId="formBasicPassword">
               
                <Form.Control type="password" placeholder="Password" />
            </Form.Group>
            <Form.Group controlId="formBasicCheckbox">
                <Form.Check type="checkbox" label="Check me out" />
            </Form.Group>
            <Button variant="primary" type="submit">
                Submit
            </Button>
            </Form>
            </div>
            </div>
                    );
                }
            }
     
export default signin
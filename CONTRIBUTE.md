# Thank you!

- we're currently tracking new requests for features, bugs, and open questions via `Issues`. Feel free to open a new issue!
- we ask that changes to `master` be made via pull request


## Contributing to SafeTrace Compute
- This is SafeTrace's core service, for private compute and storage of data. Code here is written in Rust, and is executed within an Intel SGX enclave. 
- For more detail, see `/enclave`. @lacabra is leading development of this component. 

## Contributing to client application
- Currently, we are discussing the application-side and UX within `docs/ux`. 
- We are also building a simple web app interface to demonstrate the SafeTrace Compute service.
- We welcome any help on this, including: 
    - full-stack web app development 
    - UX consultation 
    - UX design
    - client-side data validation (urgent request!)
    
We also want to enable external apps to communicate with our compute service via our API. 
We welcome apps who want to use our backend to discuss their API requirements with us.

## Contributing to research
We are doing research on:
- what contact tracing tools exist
- what data is most valuable for effective contact tracing
- what is the most useful way to deploy this type of service (geographically delimited? via public health officials?)

## How to get involved:

- [open issues](https://github.com/enigmampc/SafeTrace/issues) to share ideas or questions, and feel free to leave any comments
- join the conversation happening in our [Discord](https://discord.gg/vK7b45u) and on the [dev forum](https://forum.enigma.co/t/safetrace-privacy-preserving-contact-tracing-for-covid-19/1476)
- participate in the [COVID-19 Global Hackathon](https://devpost.com/software/safetrace) March 26-30 ([discussion](https://join.slack.com/share/I010ZH2QHJB/pUfz8AQI3O41pugLTTB5BMNL/enQtMTAzMzU4MDgzMzYyMy0wYzY0YzRkYTdhYmNmZDNjMThmMjZlOTg5M2U5NDZlYWM0ODVjNTRhYTczM2VmZTA5NTIwNzRhMWNmZTQwZGU4))
- get ready for DAIA's [COVIDathon](https://daia.foundation/covidathon) which starts April 1 ([discussion](https://discord.gg/NsX9Gzb))
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

# Thank you!

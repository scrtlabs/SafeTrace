# Enigma Confidential Computing Platform
Enigma Confidential Computing Platform (ECCP) is an API which connects to a privacy-preserving storage and private computation service. ECCP allows organizations to share data in encrypted form, perform analysis to generate insights and to capture value without worrying about data liability or data privacy concerns.

This repository is for SafeTrace, an implementation of ECCP for privacy preserving contract tracing. SafeTrace allows users to privately share (encrypyted) location history and test status, to get notifications if they have been in close proximity with diagnosed individuals and to monitor higher risk locations in real-time. 

This repository is aimed to be a sample implementation of ECCP for contact tracing in the fight against Covid19. The same architecture can be used for a variety of use-cases that involve fraud in online platforms and marketplaces, machine learning for training data sets, consolidating data set and numerous other use cases. In order to use this architecture for any other user case, check out:
- the API folder to see how clients interact with the server. This focuses on local data encryption and communication of encrypted data to the server
- the Client folder for a sample integration for SafeTrace
- this document (https://github.com/enigmampc/SafeTrace/blob/7094bf340e53743950903a2febd8f3c780490296/enclave/safetrace/enclave/src/data.rs#L228) to see individual matching algorithm for SafeTrace. This algorithm can be changed with other any other algorithm for a desired use-case.

## Overview & Motivation for SafeTrace
Contact-tracing is the use of information about where an individual has been, and who they may have come into contact with, as a way to track and manage the spread of viruses. Smartphone data provides a ready source of highly detailed information that can be used to automate contact-tracing.
Automated contact-tracing applications face two problems:
- *Data Privacy*: Contact-tracing relies on accurate and granular data about the user’s location and/or proximity to other users. This data is used in conjunction with a user's infection status to determine their risk level. Collecting this type of information about users places a significant data security burden on whatever organization is gathering the data or has access to it. Methods which are privacy preserving largely sacrifice data utility.
- *Data Utility*: Existing privacy-preserving contact-tracing methods (bluetooth) only inform individuals of their risk, and are of limited use to health officials, researchers, or crisis response, who need aggregate data for research and heat maps.

We propose SafeTrace, which is an API which connects to a privacy-preserving storage and private computation service. 
This means that applications (web or mobile) can enable users to submit encrypted location and health status data for analysis via the SafeTrace API, without ever revealing plaintext data to anyone, including the SafeTrace server operator or the application. This relies on Trusted Execution Environments (TEE), a technology for preserving data privacy while data is in-use. Then, SafeTrace analysis can produce two types of reports-- individual and global-- based on the aggregate data submitted by all applications. SafeTrace can be used to overcome both privacy concerns and data utility problems for contact-tracing.

This system relies on 3 core services:

### Location History data from Google Location Services via Google Takeout

Any user who has Location Services active with Google is able to obtain a JSON format file of their location history. They are also able to edit this file manually to remove any unwanted or sensitive locations (i.e., a home address). A user who does not use Location Services can manually add a history via Google. 

***Note: This service could be swapped/replaced by a mobile application at some point***

### A Privacy-preserving Computation service

Private computation is a term for performing tasks on data that is never viewed in plaintext. Our system will use private computation to generate individual and global analytics. In this scenario, private computation techniques could be employed to:
- Identify users who have been in close proximity with individuals who have tested positive for individiual analysis
- Create heatmaps from diagnosed patients' location data, using clustering algorithms to prevent revealing of data to anyone, and output those results to a map
- Apply differential privacy techniques to diagnosed patient data to be used for research purposes
- Initially, we propose using an Intel-SGX based service that uses [Trusted Execution Environments ](https://software.intel.com/en-us/sgx/details) (TEE). Additional alternative private compute techniques include homomorphic encryption, multiparty computation, and differential privacy.

***Note: Privacy preserving analysis listed above can be extended to any kind of analysis including machine learning for other use-cases that levereage Enigma Confidential Computing Platform***

### Visualization and notification services

A graphical user interface (GUI) to:
- Inform individuals who have been in close proximity of diagnosed patients (time and location) via a notification system.
- Create a heatmaps for users (individual and social organizations) to track the current status virus outbreak at a granular level. 

These diagrams provide an overview of how these services connect and how data is accessed and controlled throughout. *Note: data is encrypted on the client side, remains encrypted in transit, and is protected by TEE security and privacy guarantees during compute.*

![image](docs/diagrams/Data-control.png)


## User Story

1. User creates an account (email and password). 
2. User views instructions for retrieving location data from Google Location services. 
3. User reviews Google Maps timeline, and optionally removes any sensitive activity (i.e., home address, work address, others)
4. User exports her data via Google Takeout service
5. User returns to app UI and uploads JSON file from Google Takeout for the previous month or two
*Steps 1-5 can also be replaced by an integration to mobile application that collects user location data such as Yelp.*
6. User indicates her current testing status (positive, negative, untested) and the date of the test (today's date if untested)
7. User submits data to compute service (data is encrypted locally by the app prior to sending)
8. User can now view "matches", where her data overlaps in time and proximity to a user reporting a positive test result
9. User can opt in to receive emails if new matches occur, and prompting her to update her data and infection status periodically.
10. User can use the global view mode to see a heatmap of locations of diagnosed patients.


## System Architecture

![image](docs/diagrams/overview.png)

The system is made up from the following components:

**Front-end UI**

- contains the self-reporting UI
- displays the individual proximity match report from post-compute results
- displays a heat map view of positively tested participants (global results) from post-compute results
*This component can would be replaced in case mobile application that collects user location uses SafeTrace API.*

**Login / Unique identifier DB**
*This component can would be replaced in case mobile application that collects user location uses SafeTrace API.*

**Private Compute Service**

- contains code
- maintains an encrpyted DB of submissions


## Components

### Data self-reporting UI
**Requirements:**
- Clearly communicates to users the goals and possible risks of the service
- Walks users through obtaining and sanitizing Google Takeout location data
- Provides https-like assurances that UI is in communication with successfully attested enclave
- Enables users to create a persistent email/password log-in
- Enables users to submit, and update:
    - 1-2 months of location history in Google Takeout JSON format
    - Current infection status (positive, negative, untested)
    - Date test was administered
- Runs data formatting and simple data validation on the browser

![img](docs/diagrams/adding-data.png)

### Private compute
**Requirements:**
- Proves what code is being executed over the data
- Proves integrity via Intel Attestation Service (IAS)

Input:
- Encrypted user location histories in Google Takeout JSON format
- Encrypted (self-reported) testing status

Output:
- Positive matches between users who have had positive test results and users who overlapped with them on time and proximity for individual reporting
- Clustering algorithm to run on location history of users who have had positive test results (with time dependend weights) for global view

Open Questions

### Post-Compute Results
Current thinking is to have two services result from the computation:
- A notification service for users who are untested/negative that tells them if they have overlapped in time/proximity with positive test cases [Link to detailed description]
- An aggregate heatmap of locations where individuals with positive tests have been [Link to detailed description]

## LICENSE

The code in this repository is released under the [MIT License](LICENSE).

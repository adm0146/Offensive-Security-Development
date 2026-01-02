# Section 1.2 - Security Concepts
**Date:** November 22, 2025  
**Source:** Professor Messer Security+ SY0-701  
**Domain:** Architecture and Design

---

## CIA Triad

**Combination of principles:**
- The fundamentals of security
- Sometimes referred to as the AIC Triad

### The Triad:

**Confidentiality:**
- Prevent disclosure of information to unauthorized individuals or systems

**Integrity:**
- Messages can't be modified without detection

**Availability:**
- Systems and networks must be up and running

---

## Breaking Down the CIA Triad:

### Confidentiality

**Definition:**
- Certain information should only be known by certain people
- Prevent unauthorized information disclosure

**Methods:**

1. **Encryption:**
   - Encode messages so only certain people can read it

2. **Access controls:**
   - Selectively restrict access to a resource 

3. **Two factor authentication:**
   - Additional confirmation before info is disclosed

---

### Integrity

**Definition:**
- Data is stored and transferred as intended
- Any modifications to data would be identified 

**Methods:**

1. **Hashing:**
   - Map data of an arbitrary length to data of a fixed length

2. **Digital signatures:**
   - Mathematical scheme to verify the integrity of data 

3. **Certificates:**
   - Combine with digital signature to verify an individual 

4. **Non-repudiation:**
   - Provides proof of integrity, can be asserted to be genuine

---

### Availability

**Definition:**
- Information is accessible to authorized users
- Always at your fingertips

**Methods:**

1. **Redundancy:**
   - Build services that will always be available

2. **Fault Tolerance:**
   - System will continue to run, even when a failure occurs 

3. **Patching:**
   - Stability
   - Close security holes

---

## Non-Repudiation

**YOU CAN'T DENY WHAT YOU HAVE SAID:**
- No take backs

**Example - Sign a contract:**
- Your signature adds non-repudiation
- You really did sign the signature
- Others can see your signature

**Cryptography Perspective:**
- Proof of integrity
- Proof of origin, with high assurance of authenticity

---

### Proof of Integrity:

**Verify data does not change:**
- The data remains accurate and consistent

**In cryptography, we use hash:**
- Represents data as a short string of text
- A message digest, a fingerprint 

**If data changes, the hash changes:**
- If the person changes, you get a different fingerprint

**Limitation:**
- Doesn't necessarily associate data with an individual
- Only tells you that data has changed

---

### Hashing Example - The Encyclopedia:

**Gutenberg Encyclopedia, VOL 1 by Project Gutenberg (8.1 megabytes)**

**Hash:**
```
C7004997a9cff73f9c3423579be5e8577389b63b4b085e541d327903f99a09db
```

**Change one character in the file:**
- The hash changes dramatically

**If the hash is different:**
- Something has changed
- The data integrity has been compromised

---

### Proof of Origin:

**Three Goals:**
1. Prove the message was not changed (Integrity)
2. Prove the source of the message (Authentication)
3. Make sure the signature isn't fake (Non-repudiation)

**Sign with a private key:**
- The message doesn't need to be encrypted
- Nobody else can sign this

**Verify with the public key:**
- Any change to the message will invalidate the signature

---

## Creating a Digital Signature:

**Step 1:** Alice sends a plaintext document with "You're hired Bob" 
- Hashing algorithm will generate a hash for that plaintext document

**Step 2:** A hash of the plaintext is created 

**Step 3:** The hash of the plaintext gets encrypted with Alice's private key

**Step 4:** Digital Signature is made with the private key

**Step 5:** The plaintext is now associated with a digital signature
- Both are sent to Bob attached together

---

## Verifying a Digital Signature:

**Step 1:** Bob receives plaintext document with the digital signature

**Step 2:** Bob uses Alice's public key to decrypt the digital signature

**Step 3:** Once decryption is complete, we should get the original hash
- No data should have been changed since encryption took place with Alice's key

**Step 4:** Bob verifies the hash by:
- Creating his own hash of the plaintext document
- Running it through the same hashing algorithm
- Comparing the before and after hash to see if they are the same

---

## Authentication, Authorization and Accounting (AAA)

### AAA Framework:

**Identification:**
- This is who you claim to be
- Usually your username

**Authentication:**
- Prove you are who you say you are
- Password and other authentication factors

**Authorization:**
- Based on your identification and authentication, what access do you have?

**Accounting:**
- Resources used:
  - Login time
  - Data sent and received
  - Logout time

---

## Authenticating People:

**Step 1:** Client tries to access the internal file server
- VPN/Firewall prompts a login

**Step 2:** All login credentials are normally stored on a separate server (AAA server)
- Checks if the information provided by the client matches a user in the AAA server
- If match is true, it sends that information back to the VPN/Firewall
- Approves the client into the internal server

---

## Authenticating Systems:

**Challenge:**
- You have to manage many devices
- Often devices you'll never physically see
- A system can't type a password
- You may not want to store one

**Solution:**
- Put a digitally signed certificate on the device

**Benefits:**
- Other business processes rely on the certificate
- Access to VPN from authorized devices
- Management software can validate the end device

---

### Certificate Authentication:

**Organization has trusted Certificate Authority (CA):**
- Most organizations maintain their own CAs

**Process:**
1. Organization creates a certificate for a device
2. Digitally signs the certificate with the organization's CA
3. Certificate is included on device as an authentication factor
4. CA's digital signature is used to validate the certificate

**Certificate-based authentication:**
- Compare the certificate from the laptop to the root certificate
- If valid, allow access

---

## Authorization Models:

**After Authentication:**
- The user or device has now authenticated
- To what do they now have access?
- Time to apply an authorization model

**Purpose:**
- Users and services → data and applications
- Associating individual users to access rights does not scale

**Solution:**
- Put an authorization model in the middle
- Define by roles, organizations, attributes, etc.

---

### No Authorization Model:

**Simple relationship:**
- User → Resource 

**Issues with this method:**
- Difficult to understand why an authorization may exist
- Does not scale

---

### Using an Authorization Model:

**Add an abstraction:**
- Reduce complexity 
- Create a clear relationship between the user and the resource

**Benefits:**
- Admin is streamlined
- Easy to understand the authorizations
- Support any number of users or resources

---

## Gap Analysis

**Definition:**
- Where you are compared with where you want to be
- The "gap" between the two

**Requirements:**
- May require extensive research
- There's a lot to consider
- Can take weeks or months
- Extensive study of numerous participants
- Get ready for emails, data gathering, and technical research

---

### Choosing a Framework:

**Work towards a known baseline:**
- This may be an internal set of goals
- Some orgs should use formal standards

**Determine the end goal:**
- NIST Special Publication 800-171 Revision 2
  - Protecting Controlled Unclassified Information in non-federal systems and organizations
- ISO/IEC 27001
  - Information security management systems

---

### Evaluate People and Processes:

**Formal experience:**
- Current training 
- Knowledge of security policies and procedures

**Examine the current processes:**
- Research existing IT systems 
- Evaluate existing security processes

---

### Compare and Contrast:

**The comparison:**
- Evaluate existing systems 

**Identify weaknesses:**
- Along with the most effective processes

**A detailed analysis:**
- Examine broad security categories 
- Break those into smaller segments 

---

### The Analysis and Report:

**The final comparison:**
- Detailed baseline objectives
- A clear view of the current state

**Need a path:**
- Get from current security to goal
- Will include time, money and lots of change control

**Time to create a gap analysis:**
- A formal description of the current state 
- Recommendations for meeting baseline

---

## Zero Trust

**Traditional Networks:**
- Relatively open on the inside 
- Once you're through the firewall, there are few security controls

**Zero Trust Definition:**
- A holistic approach to network security
- Covers every device, every process, every person
- Everything must be verified
- Nothing is inherently trusted

**Includes:**
- Multi-factor authentication
- Encryption
- System permissions
- Additional firewalls
- Monitoring and analytics

---

### Planes of Operation:

**Split Network into functional planes:**
- Applies to physical, virtual, and cloud components 

**Data Plane:**
- Process the frames, packets, and network data
- Processing, forwarding, trunking, encrypting, NAT

**Control Plane:**
- Manages the actions of the data plane
- Define policies and rules
- Determines how packets should be forwarded
- Routing tables, session tables, NAT tables

**Extend to physical architecture:**
- Incorporate into hardware and software

---

### Controlling Trust:

**Adaptive Identity:**
- Consider the source and the requested resources
- Multiple risk indicators:
  - Relationship to the organization
  - Physical location
  - Type of connection
  - IP address, etc.
- Make the authentication stronger if needed

**Threat Scope Reduction:**
- Decrease the number of possible entry points

**Policy Driven Access Control:**
- Combine the adaptive identity with a predefined set of rules

---

### Security Zones:

**Security is more than a one-to-one relationship:**
- Broad categorizations provide a security-related function

**Where are you coming from and where are you going:**
- Trusted, untrusted
- Internal network, external network
- VPN1, VPN2, VPN 11
- Marketing, IT, accounting, HR

**Using zones may be enough by itself to deny access:**
- Example: Untrusted to trusted zone traffic

**Some zones are implicitly trusted:**
- Example: Trusted to internal zone traffic 

---

### Policy Enforcement Point (PEP):

**Subjects and systems:**
- End users, applications, non-human entities

**Policy enforcement point (PEP):**
- The gatekeeper of traffic
- Allow, monitor, and terminate connections
- Can consist of multiple components working together

**Applying trust in the planes:**
- There's a process for making an authentication decision

**Policy Engine:**
- Evaluates each access decision based on policy and other information sources
- Grant, deny or revoke

**Policy Administrator:**
- Communicates with the policy enforcement (gatekeeper)
- Generates access tokens or credentials 
- Tells PEP to allow or don't allow access

---

## Physical Security

**Goal:**
- Prevent Access
- There are limits to prevention 

---

### Barricades and Bollards:

**Purpose:**
- Channel people through a specific access point
- Keep out other things
- Allow people, prevent cars and trucks

**Benefits:**
- Identify safety concerns
- Also prevent injuries 

**Can be used to an extreme:**
- Concrete barriers / bollards
- Moats

---

### Access Control Vestibules:

**Configuration Options:**

1. **All doors normally unlocked:**
   - Opening one door causes others to lock

2. **All doors normally locked:**
   - Unlocking one door prevents others from being unlocked

3. **One door open / other locked:**
   - When one is open, the other cannot be unlocked

4. **One at a time, controlled groups:**
   - Managed control through an area

---

### Fencing:

**Characteristics:**
- Usually very obvious
- May not be what you're looking for

**Options:**
- **Transparent or opaque:** See through the fence or not
- **Robust:** Difficult to cut the fence
- **Prevent climbing:** Razor wire, build it high

---

### Video Surveillance:

**CCTV (Closed Circuit Television):**
- Can replace physical guards

**Camera features are important:**
- Motion recognition can alarm and alert when something moves
- Object detection can identify a license plate or person's face
- Often many different cameras networked together and recorded over time

---

### Guards and Access Badges:

**Security Guard:**
- Physical protection at the reception area of facility
- Validates identification of existing employees

**Two Person Integrity/Control:**
- Minimize exposure to an attack
- No single person has access to a physical asset

**Access Badge:**
- Picture, name, other details
- Must be worn at all times
- Electronically logged

---

### Lighting:

**Principle:**
- More light means more security
- Attackers avoid the light
- Easier to see when lit
- Non-IR cameras can see better

**Specialized Design:**
- Consider overall light levels
- Lighting angles may be important (important for facial recognition)
- Avoid shadows and glare

---

### Sensors:

**Infrared:**
- Detects infrared radiation in both light and dark
- Common motion detectors 

**Pressure Sensors:**
- Detects a change in force 
- Floor or window sensors

**Microwave:**
- Detects movement over large areas

**Ultrasonic:**
- Send ultrasonic signals, receive reflected sound waves 
- Detect motion, collision detection, etc.

---

## Deception and Disruption

### Honeypots:

**Purpose:**
- Attract the bad guys and trap them there

**Reality:**
- The attacker is probably a machine
- Makes for interesting recon

**Implementation:**
- Create a virtual world to explore
- Many different options (most are open source and available to download)
- Constant battle to discern the real from fake

---

### Honey Nets:

**Concept:**
- A real network includes more than a single device
- Servers, workstations, routers, switches, firewalls

**Honeynets:**
- Build larger deception network with one or more honeypots
- More than one source of information

**Example:**
- Stop spammers - https://projecthoneypot.org

---

### Honeyfiles:

**Purpose:**
- Create files with fake information
- Something bright and shiny

**Implementation:**
- Bait for the honey net (passwords.txt)
- Add many honey file shares

**Alert:**
- An alert is sent if the file is accessed
- Virtual bear trap

---

### Honey Tokens:

**Purpose:**
- Track malicious actors
- Add some traceable data to the honey net
- If the data is stolen, you'll know where it came from

**Examples:**

1. **API Credentials:**
   - Does not actually provide access 
   - Notifications are sent when used

2. **Fake Email Addresses:**
   - Add it to a contact list
   - Monitor the internet to see who posts it

3. **Many other honey token examples:**
   - Database records
   - Browser cookies
   - Web page pixels

---

## Key Takeaways for Exam:

✅ **CIA Triad** - Confidentiality, Integrity, Availability (know all three!)
✅ **Non-repudiation** - You can't deny what you did
✅ **Digital signatures** - Prove integrity and origin
✅ **AAA** - Authentication, Authorization, Accounting
✅ **Zero Trust** - Never trust, always verify
✅ **Physical security layers** - Defense in depth
✅ **Deception techniques** - Honeypots, honeynets, honeyfiles, honey tokens

---

*Notes completed: November 22, 2025*  
*Next: Section 1.3 - Application Attacks*

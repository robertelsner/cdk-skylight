![](https://img.shields.io/badge/CDK%20Skylight-Developer%20Preview-orange.svg?style=for-the-badge)

# CDK Skylight

CDK Skylight is a set of code libraries written with AWS CDK that enables customers to create & provision highly reliable, scalable, and cost-effective applications within the **Microsoft products ecosystem** without worrying about creating and configuring the underlying AWS infrastructure components. (Such as .NET Workloads, Active Directory, SQL Server, NetApp ONTap). CDK Skylight is set to address repetitive tasks and best practices involved with managing, deploying, and integrating those apps. 

In addition to the complexity of integrating the "AWS side" products, Microsoft technologies such as SQL, AD, Windows OS require OS-level integration and optimization. Skylight help in both the "AWS-side" and the "OS-side," offering a complete end-to-end configuration and integration solution of AWS products. 
# Who should use CDK Skylight?

The primary persona to use CDK Skylight is the infrastructure team owners to customize the stacks and provide them to the application owners teams.

For applications that require Active Directory, the application team relies on different teams that handle this part. Therefore, the integration between the application and the Active Directory happens in a dedicated environment. With CDK Skylight, the Active Directory's team owner can provide a custom stack using a pre-defined stack to the teams relying on this Component, allowing the application owner to build the same configuration in the developer account.

# When to use CDK Skylight?

CDK Skylight aims to help in all application lifecycle stages, from the developer’s machine to production environments.


# How to use

```bash
npm install cdk-skylight
```

In your CDK App

```typescript
import * as skylight from "cdk-skylight";

new skylight.authentication.AdAuthentication(scope: Construct, id: string, props: IADAuthenticationProps)

```

# CDK Skylight Constructs 

## Skylight-Compute

Library of Custom Compute components 

### DomainWindowsNode

A Domain Windows Node Construct represents one Windows EC2 instance configured with Active Directory.

The DomainWindowsNode can be customized to different instance sizes and additional permissions set just like any other EC2 Instance.
You can use this construct to run elevated domain tasks with domain permissions or run your application in a single instance setup.

The machine will be joined to the provided Active Directory domain using a custom CloudFormation bootstrap that will wait until the required reboot to join the domain. Then it will register the machine in SSM and pull tasks from the SSM State manager.

You can send tasks to that machine using the provided methods: runPsCommands() and runPSwithDomainAdmin()

```typescript
const windowsNodeObject = new skylight.compute.DomainWindowsNode(
    stack,
    'WindowsNode',
    {
      vpc: vpc,
      madSsmParameters: {}, //pointer to the Secret that holds the Domain Admin username and password
    },
  );

// Special Methods:
windowsNodeObject.runPsCommands(['echo hello-world'], 'hello');
windowsNodeObject.runPSwithDomainAdmin(['Write-Host hello-world'], 'hello-withPS');
windowsNodeObject.openRDP('1.1.1.1/32');

```
## Skylight-Authentication

Library of Custom Authentication components 

### **AdAuthentication** - Manged Active Directory with R53 Resolvers 

A Ad Authentication represents an integration pattern of Managed AD and Route 53 Resolver in a specific VPC, it will create Managed AD with the provided Secret (Secrets Manager) or generates a new Secret.

The secret saved to SSM parameter store so others can use it with other Constructs (Such as Windows node or FSx)
The provided VPC or the new created VPC will be configured to forward DNS requests to the Managed AD with Route53 Resolvers

The construct also creates (optionally) t3.nano machine that is part of the domain that can be used to run admin-tasks (such as createADGroup)
The createADGroup() method creates an Active Directory permission group in the domain, using the domain admin user.

Please note: When calling createADGroup() API, a Lambda will be created to start the worker machine (Using AWS-SDK),
then each command will be scheduled with State Manager, and the instance will be shut down after complete.

Example:

```typescript
new skylight.authentication.AdAuthentication(
	stack,
	'AdAuthentication2',
	{
		vpc: vpc,
		edition: 'enterprise', // Optional
		secret: new Secret(stack, 'test-secret'), // Optional
		domainName: 'test-domain', // Optional
		secretName: 'custom-secret-name', // Optional
		createWorker: false, // Optional
	},
);
```

## Skylight-Storage
### FSxWindows 

A FSxWindows represents an integration pattern of Amazon FSx and Managed AD in a specific VPC.
The Construct creates Amazon FSx for Windows 

The construct also creates t3.nano machine that is part of the domain that can be used to run admin-tasks (such as createFolder)
The createFolder() method creates an SMB Folder in the FSx filesystem, using the domain admin user.

Please note: When calling createFolder() API, a Lambda will be created to start the worker machine (Using AWS-SDK), then each command will be scheduled with State Manager, and the instance will be shut down after complete.

Example:

```typescript
this.fsxWindows = new skylight.storage.FSxWindows(this, "FSx", {
	vpc: vpc,
	adParametersStore: adParametersStore
});
this.fsxWindows.createFolder("containerStorage");
```

# Very experimental Libraries 

### EKS Compute

The stack creates the Windows Autoscaling group with domain join script and the SSM Documents for gMSA and Global Mapping.

### EKS Cluster

```typescript
const cluster = new WindowsEKSCluster(stack, "ElasticCluster" , { vpc : new aws_ec2.Vpc(stack, 'MyVpc', {})}) // Creates EKS Cluster with Windows support
```

### EKS Nodes

This stack takes the PersistentStorage stack as input and creates the EKS cluster with permissions to operate EKS clusters.

```typescript
const myNodes = new WindowsEKSNodes( // Creates AutoScaling group for Windows Support
    stack,
    'WindowsEKSNodes',
    {
		vpc: new aws_ec2.Vpc(stack, 'MyVpc', {})
	}
  )

myNodes.addAdDependency(secretObject);
myNodes.addStorageDependency(secretObject, storageMount);
myNodes.addEKSDependency(eks_cluster.eksCluster);
myNodes.addLocalCredFile(secretObject, 'myEKSNodes', 'myWebApp');
```

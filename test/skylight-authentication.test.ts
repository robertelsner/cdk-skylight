import { App, aws_ec2, Stack } from 'aws-cdk-lib';
// import { Template } from 'aws-cdk-lib/assertions';
import { SubnetType } from 'aws-cdk-lib/aws-ec2';
import { Secret } from 'aws-cdk-lib/aws-secretsmanager';
import * as skylight from '../src';

const env = {
  account: '1111111111',
  region: 'us-east-1',
};
const app = new App();
const stack = new Stack(app, 'test', { env: env });
const vpc = new aws_ec2.Vpc(stack, 'vpc', {});
const vpcWithCustomSubnets = new aws_ec2.Vpc(stack, 'vpcwithsub', {
  maxAzs: 2,
  subnetConfiguration: [
    { name: 'Data', subnetType: SubnetType.PRIVATE_WITH_EGRESS },
    { name: 'Public', subnetType: SubnetType.PUBLIC },
  ],
});

test('authentication', () => {
  const mad = new skylight.authentication.AwsManagedMicrosoftAdR53(
    stack,
    'AwsManagedMicrosoftAdR53',
    {
      vpc: vpc,
      createWorker: true,
    },
  );
  const madwithoutr53 = new skylight.authentication.AwsManagedMicrosoftAd(
    stack,
    'madWithoutR53',
    {
      vpc: vpc,
      createWorker: false,
    },
  );
  const mad2 = new skylight.authentication.AwsManagedMicrosoftAdR53(
    stack,
    'AwsManagedMicrosoftAd2',
    {
      vpc: vpc,
      edition: 'enterprise',
      secret: new Secret(stack, 'test-secret'),
      domainName: 'test-domain',
      secretName: 'custom-secret-name',
      createWorker: false,
    },
  );
  const mad3 = new skylight.authentication.AwsManagedMicrosoftAdR53(
    stack,
    'AwsManagedMicrosoftAd3',
    {
      vpc: vpc,
      edition: 'enterprise',
      secretName: 'custom-secret-name',
      configurationStore: {
        namespace: 'custom-namespace',
        secretPointer: 'secret-pointer',
        directoryIDPointer: 'directory-pointer',
      },
      createWorker: false,
    },
  );
  const mad4 = new skylight.authentication.AwsManagedMicrosoftAdR53(
    stack,
    'AwsManagedMicrosoftAd4',
    {
      vpc: vpcWithCustomSubnets,
      vpcSubnets: vpcWithCustomSubnets.selectSubnets({
        subnetGroupName: 'Data',
      }),
      edition: 'enterprise',
      secretName: 'custom-secret-name',
      configurationStore: {
        namespace: 'custom-namespace',
        secretPointer: 'secret-pointer',
        directoryIDPointer: 'directory-pointer',
      },
      createWorker: false,
    },
  );

  mad.createADGroup('Test', 'test2');
  mad.createServiceAccount('test', 'Test2', 'test3');
  expect(mad2).toHaveProperty(
    'adParameters.namespace',
    'cdk-skylight/authentication/mad',
  );
  expect(madwithoutr53).toHaveProperty(
    'adParameters.namespace',
    'cdk-skylight/authentication/mad',
  );
  expect(mad3).toHaveProperty(
    'adParameters.namespace',
    'custom-namespace/authentication/mad',
  );
  expect(mad).toHaveProperty(
    'microsoftAD.cfnResourceType',
    'AWS::DirectoryService::MicrosoftAD',
  );
  expect(mad4).toHaveProperty(
    'microsoftAD.vpcSettings.subnetIds',
    vpcWithCustomSubnets.selectSubnets({ subnetGroupName: 'Data' }).subnetIds,
  );
  expect(mad).toHaveProperty('domainWindowsNode');
  expect(mad2).toHaveProperty('domainWindowsNode', undefined);
  expect(mad).toHaveProperty(
    'domainWindowsNode.instance.instance.subnetId',
    vpc.selectSubnets({
      availabilityZones: [Stack.of(stack).availabilityZones[0]],
      subnetType: SubnetType.PRIVATE_WITH_EGRESS,
    }).subnetIds[0],
  );
});

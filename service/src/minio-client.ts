import { Client, type ClientOptions } from 'minio';
import logger from './fileServerLogger';
import { S3Client } from '@aws-sdk/client-s3';
import {
    fromContainerMetadata,
    fromInstanceMetadata,
    fromTokenFile,
} from '@aws-sdk/credential-providers';

export async function createMinioClient(): Promise<Client> {
    const irsaExplicit = process.env.MINIO_USE_IRSA?.toLowerCase() === 'true';
    const irsaEnvVars =
        Boolean(process.env.AWS_WEB_IDENTITY_TOKEN_FILE) &&
        Boolean(process.env.AWS_ROLE_ARN);
    const useIrsa = irsaExplicit || irsaEnvVars;

    const baseConfig: ClientOptions = {
        // Unknown-length streams otherwise grow SDK parts to 528 MiB (the 5 TiB
        // object limit / 10,000 parts). Bound each multipart buffer instead.
        partSize: 8 * 1024 * 1024,
        endPoint: process.env.MINIO_ENDPOINT ?? 'localhost',
        port:
            process.env.MINIO_NO_PORT?.toLowerCase() === 'true'
                ? undefined
                : parseInt(process.env.MINIO_PORT ?? '9000'),
        useSSL: process.env.MINIO_USE_SSL?.toLowerCase() === 'true',
        region:
            process.env.MINIO_REGION ?? process.env.AWS_REGION ?? 'us-east-1',
    };

    if (useIrsa) {
        // MinIO expects EC2's Code/AccessKeyID fields, which ECS does not return.
        // The AWS SDK handles ECS, web identity and credential expiration.
        const workload = process.env.AWS_WEB_IDENTITY_TOKEN_FILE
            ? fromTokenFile({ clientConfig: { region: baseConfig.region } })
            : process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI ||
                process.env.AWS_CONTAINER_CREDENTIALS_FULL_URI
              ? fromContainerMetadata({ timeout: 1500, maxRetries: 2 })
              : fromInstanceMetadata({ timeout: 1500, maxRetries: 2 });
        // Use only workload identity sources; never fall back to a host profile.
        const resolveCredentials = new S3Client({
            region: baseConfig.region,
            credentials: workload,
        }).config.credentials;
        // MinIO's constructor consumes credential getters; its nominal provider
        // classes are not exported. Keep the adapter at that public option edge.
        const credentialsProvider = {
            async getCredentials() {
                const credentials = await resolveCredentials();
                return {
                    getAccessKey: () => credentials.accessKeyId,
                    getSecretKey: () => credentials.secretAccessKey,
                    getSessionToken: () => credentials.sessionToken,
                };
            },
        } as unknown as NonNullable<ClientOptions['credentialsProvider']>;
        logger.info(
            'Using AWS SDK workload credentials for S3 authentication',
            { region: baseConfig.region },
        );
        return new Client({ ...baseConfig, credentialsProvider });
    }

    logger.info('Using explicit credentials for MinIO/S3 authentication');
    return new Client({
        ...baseConfig,
        accessKey: process.env.MINIO_ACCESS_KEY ?? '',
        secretKey: process.env.MINIO_SECRET_KEY ?? '',
        sessionToken: process.env.MINIO_SESSION_TOKEN,
    });
}

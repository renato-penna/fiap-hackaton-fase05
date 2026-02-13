"""Classificação de componentes cloud em categorias STRIDE."""

from enum import Enum


class ComponentCategory(str, Enum):
    """Categorias de componentes cloud suportadas."""

    COMPUTE = "compute"
    DATABASE = "database"
    STORAGE = "storage"
    NETWORK = "network"
    SECURITY = "security"
    API_GATEWAY = "api_gateway"
    MESSAGING = "messaging"
    MONITORING = "monitoring"
    IDENTITY = "identity"
    ML_AI = "ml_ai"
    DEVOPS = "devops"
    SERVERLESS = "serverless"
    ANALYTICS = "analytics"
    GROUPS = "groups"
    OTHER = "other"


# Mapeamento de nomes de componentes para categorias
_COMPONENT_MAP: dict[str, ComponentCategory] = {
    # Compute
    "EC2": ComponentCategory.COMPUTE,
    "ECS": ComponentCategory.COMPUTE,
    "EKS": ComponentCategory.COMPUTE,
    "Fargate": ComponentCategory.COMPUTE,
    "Lambda": ComponentCategory.COMPUTE,
    "Lightsail": ComponentCategory.COMPUTE,
    "Batch": ComponentCategory.COMPUTE,
    "Beanstalk": ComponentCategory.COMPUTE,
    "VM": ComponentCategory.COMPUTE,
    "App Service": ComponentCategory.COMPUTE,
    "Container": ComponentCategory.COMPUTE,
    "Compute Engine": ComponentCategory.COMPUTE,
    "GKE": ComponentCategory.COMPUTE,
    "Cloud Run": ComponentCategory.COMPUTE,
    "SEI": ComponentCategory.COMPUTE,
    "SIP": ComponentCategory.COMPUTE,
    "Server": ComponentCategory.COMPUTE,
    "Vm Scaleset": ComponentCategory.COMPUTE,
    "Virtual Machine": ComponentCategory.COMPUTE,
    "Elastic Container Service": ComponentCategory.COMPUTE,
    # Database
    "RDS": ComponentCategory.DATABASE,
    "DynamoDB": ComponentCategory.DATABASE,
    "Aurora": ComponentCategory.DATABASE,
    "ElastiCache": ComponentCategory.DATABASE,
    "Redis": ComponentCategory.DATABASE,
    "Redshift": ComponentCategory.DATABASE,
    "Neptune": ComponentCategory.DATABASE,
    "DocumentDB": ComponentCategory.DATABASE,
    "Cosmos DB": ComponentCategory.DATABASE,
    "SQL Database": ComponentCategory.DATABASE,
    "Cloud SQL": ComponentCategory.DATABASE,
    "Firestore": ComponentCategory.DATABASE,
    "Bigtable": ComponentCategory.DATABASE,
    "MySQL": ComponentCategory.DATABASE,
    "PostgreSQL": ComponentCategory.DATABASE,
    "Table": ComponentCategory.DATABASE,
    "DB": ComponentCategory.DATABASE,
    "Oracle DB": ComponentCategory.DATABASE,
    "Mongo DB": ComponentCategory.DATABASE,
    "Memcached": ComponentCategory.DATABASE,
    # Storage
    "S3": ComponentCategory.STORAGE,
    "EBS": ComponentCategory.STORAGE,
    "EFS": ComponentCategory.STORAGE,
    "Glacier": ComponentCategory.STORAGE,
    "Blob Storage": ComponentCategory.STORAGE,
    "Cloud Storage": ComponentCategory.STORAGE,
    "FSx": ComponentCategory.STORAGE,
    "Storage Gateway": ComponentCategory.STORAGE,
    "File share": ComponentCategory.STORAGE,
    "Snowball": ComponentCategory.STORAGE,
    "Backup": ComponentCategory.STORAGE,
    "DataSync": ComponentCategory.STORAGE,
    # Network
    "VPC": ComponentCategory.NETWORK,
    "VPC Router": ComponentCategory.NETWORK,
    "Internet Gateway": ComponentCategory.NETWORK,
    "NAT Gateway": ComponentCategory.NETWORK,
    "Transit Gateway": ComponentCategory.NETWORK,
    "Direct Connect": ComponentCategory.NETWORK,
    "Private Link": ComponentCategory.NETWORK,
    "V-net": ComponentCategory.NETWORK,
    "Private Subnet": ComponentCategory.NETWORK,
    "Public Subnet": ComponentCategory.NETWORK,
    "Endpoint": ComponentCategory.NETWORK,
    "Customer Gateway": ComponentCategory.NETWORK,
    "VP Gateway": ComponentCategory.NETWORK,
    "CloudFront": ComponentCategory.NETWORK,
    "Route 53": ComponentCategory.NETWORK,
    "Route53": ComponentCategory.NETWORK,
    "Cloud Map": ComponentCategory.NETWORK,
    "ELB": ComponentCategory.NETWORK,
    "ALB": ComponentCategory.NETWORK,
    "NLB": ComponentCategory.NETWORK,
    "Load Balancer": ComponentCategory.NETWORK,
    "CDN": ComponentCategory.NETWORK,
    "Distribution": ComponentCategory.NETWORK,
    "Edge Location": ComponentCategory.NETWORK,
    # Security
    "WAF": ComponentCategory.SECURITY,
    "Shield": ComponentCategory.SECURITY,
    "GuardDuty": ComponentCategory.SECURITY,
    "KMS": ComponentCategory.SECURITY,
    "Key Management Service": ComponentCategory.SECURITY,
    "CloudHSM": ComponentCategory.SECURITY,
    "Secrets Manager": ComponentCategory.SECURITY,
    "Security Hub": ComponentCategory.SECURITY,
    "Certificate": ComponentCategory.SECURITY,
    "Certificate Manager": ComponentCategory.SECURITY,
    "Firewall": ComponentCategory.SECURITY,
    "Network Firewall": ComponentCategory.SECURITY,
    "Firewall Manager": ComponentCategory.SECURITY,
    "Inspector Agent": ComponentCategory.SECURITY,
    "Macie": ComponentCategory.SECURITY,
    "Detective": ComponentCategory.SECURITY,
    "Key vault": ComponentCategory.SECURITY,
    "Security Group": ComponentCategory.SECURITY,
    # API Gateway
    "API Gateway": ComponentCategory.API_GATEWAY,
    "API-Gateway": ComponentCategory.API_GATEWAY,
    "App gateway": ComponentCategory.API_GATEWAY,
    "AppSync": ComponentCategory.API_GATEWAY,
    "Appsync": ComponentCategory.API_GATEWAY,
    "Apigee": ComponentCategory.API_GATEWAY,
    "API Management": ComponentCategory.API_GATEWAY,
    # Messaging
    "SQS": ComponentCategory.MESSAGING,
    "SNS": ComponentCategory.MESSAGING,
    "SES": ComponentCategory.MESSAGING,
    "EventBridge": ComponentCategory.MESSAGING,
    "Event Bus": ComponentCategory.MESSAGING,
    "Kinesis": ComponentCategory.MESSAGING,
    "Kinesis Data Streams": ComponentCategory.MESSAGING,
    "Service Bus": ComponentCategory.MESSAGING,
    "Pub/Sub": ComponentCategory.MESSAGING,
    "MQ": ComponentCategory.MESSAGING,
    # Monitoring
    "CloudWatch": ComponentCategory.MONITORING,
    "Cloud Watch": ComponentCategory.MONITORING,
    "CloudWatch Alarm": ComponentCategory.MONITORING,
    "CloudTrail": ComponentCategory.MONITORING,
    "Cloud Trail": ComponentCategory.MONITORING,
    "X-Ray": ComponentCategory.MONITORING,
    "Cloud Monitoring": ComponentCategory.MONITORING,
    "Azure monitor": ComponentCategory.MONITORING,
    "Grafana": ComponentCategory.MONITORING,
    "Prometheus": ComponentCategory.MONITORING,
    "Flow logs": ComponentCategory.MONITORING,
    "Config": ComponentCategory.MONITORING,
    "Trusted Advisor": ComponentCategory.MONITORING,
    # Identity
    "IAM": ComponentCategory.IDENTITY,
    "IAM Role": ComponentCategory.IDENTITY,
    "Cognito": ComponentCategory.IDENTITY,
    "AAD": ComponentCategory.IDENTITY,
    "Active Directory Service": ComponentCategory.IDENTITY,
    "Sign-On": ComponentCategory.IDENTITY,
    "Users": ComponentCategory.IDENTITY,
    "Client": ComponentCategory.OTHER,
    # ML/AI
    "Sagemaker": ComponentCategory.ML_AI,
    "Rekognition": ComponentCategory.ML_AI,
    "Comprehend": ComponentCategory.ML_AI,
    "Lex": ComponentCategory.ML_AI,
    "Textract": ComponentCategory.ML_AI,
    "Transcribe": ComponentCategory.ML_AI,
    "Translate": ComponentCategory.ML_AI,
    "Vertex AI": ComponentCategory.ML_AI,
    "Machine Learning": ComponentCategory.ML_AI,
    "Notebook": ComponentCategory.ML_AI,
    # DevOps
    "CodePipeline": ComponentCategory.DEVOPS,
    "CodeBuild": ComponentCategory.DEVOPS,
    "CodeCommit": ComponentCategory.DEVOPS,
    "CodeDeploy": ComponentCategory.DEVOPS,
    "Jenkins": ComponentCategory.DEVOPS,
    "Github": ComponentCategory.DEVOPS,
    "Git": ComponentCategory.DEVOPS,
    "Docker Image": ComponentCategory.DEVOPS,
    "Image Builder": ComponentCategory.DEVOPS,
    "CloudFormation Stack": ComponentCategory.DEVOPS,
    "Terraform": ComponentCategory.DEVOPS,
    "Deploy Stage": ComponentCategory.DEVOPS,
    "Build Environment": ComponentCategory.DEVOPS,
    # Serverless
    "Amplify": ComponentCategory.SERVERLESS,
    "AppFlow": ComponentCategory.SERVERLESS,
    "Step Functions": ComponentCategory.SERVERLESS,
    "Step Function": ComponentCategory.SERVERLESS,
    # Analytics
    "Athena": ComponentCategory.ANALYTICS,
    "Glue": ComponentCategory.ANALYTICS,
    "BigQuery": ComponentCategory.ANALYTICS,
    "EMR": ComponentCategory.ANALYTICS,
    # Groups
    "groups": ComponentCategory.GROUPS,
    "Availability Zone": ComponentCategory.GROUPS,
    "Region": ComponentCategory.GROUPS,
}


class CategoryClassifier:
    """Classifica componentes cloud em categorias STRIDE."""

    def __init__(self, custom_mappings: dict[str, str] | None = None) -> None:
        self._component_map: dict[str, ComponentCategory] = dict(_COMPONENT_MAP)
        if custom_mappings:
            for key, value in custom_mappings.items():
                self._component_map[key] = ComponentCategory(value)

    def classify(self, component_name: str) -> ComponentCategory:
        """Classifica um componente na categoria apropriada.

        Args:
            component_name: Nome do componente detectado.

        Returns:
            A categoria do componente.
        """
        if not component_name or not component_name.strip():
            return ComponentCategory.OTHER

        # Busca exata
        if component_name in self._component_map:
            return self._component_map[component_name]

        # Busca parcial (case-insensitive)
        name_lower = component_name.lower()
        for key, category in self._component_map.items():
            if key.lower() in name_lower or name_lower in key.lower():
                return category

        return ComponentCategory.OTHER

    @property
    def supported_components(self) -> list:
        """Lista de componentes suportados."""
        return sorted(self._component_map.keys())

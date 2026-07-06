from typing import List, Dict, Tuple, Any

class M11GraphAudit:
    """
    Modulo M11: Graph-API Audit.
    Especializado en auditoria de GraphQL y gRPC.
    """
    def __init__(self):

        self.introspection_query = """
          query IntrospectionQuery {
            __schema {
              queryType { name }
              mutationType { name }
              subscriptionType { name }
              types {
                ...FullType
              }
            }
          }
          fragment FullType on __Type {
            kind
            name
            fields(includeDeprecated: true) {
              name
              args {
                ...InputValue
              }
              type {
                ...TypeRef
              }
            }
          }
          fragment InputValue on __InputValue {
            name
            type { ...TypeRef }
          }
          fragment TypeRef on __Type {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
        """

    def generate_graphql_suite(self, url: str) -> List[Tuple[Any, float, str]]:
        """
        Genera una suite de ataques GraphQL (Introspeccion, DoS, Batching).
        Retorna (body_dict, risk_score, type_label).
        """
        suite: List[Tuple[Any, float, str]] = []
        

        suite.append(({"query": self.introspection_query}, 0.8, "introspection"))
        

        dos_query = "{ me { friends { friends { friends { friends { name } } } } } }"
        suite.append(({"query": dos_query}, 0.9, "dos_recursive"))
        

        batch_attack = [
            {"query": "{ me { name } }"},
            {"query": "{ me { id } }"},
            {"query": "{ me { name } }"}
        ]
        suite.append((batch_attack, 0.7, "batching_attack"))

        return suite

    def analyze_graph_response(self, response_data: Dict, attack_type: str) -> Tuple[bool, str, float]:
        """
        Analiza las respuestas de GraphQL para confirmar vulnerabilidades.
        """
        if not response_data:
            return False, "", 0.0

        if attack_type == "introspection":
            if "__schema" in str(response_data):
                return True, "Fuga de esquema mediante Introspeccion activa", 1.0
        
        if attack_type == "dos_recursive":


            resp_str = str(response_data)
            has_protection = (
                "too complex" in resp_str.lower() or
                "query depth" in resp_str.lower() or
                "overload" in resp_str.lower() or
                "complexity" in resp_str.lower()
            )
            if has_protection:

                return False, "Servidor tiene proteccion de profundidad/complejidad activa", 0.0
            

            if "data" in response_data and response_data.get("data"):
                return True, "Query recursiva procesada sin restriccion de profundidad (Resource Exhaustion)", 0.8

        if attack_type == "batching_attack":
            if isinstance(response_data, list) and len(response_data) > 1:
                return True, "Endpoint permite Batching de consultas (Multi-query)", 0.9

        return False, "", 0.0

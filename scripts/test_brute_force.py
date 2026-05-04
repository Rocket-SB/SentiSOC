import requests
import time

# 1. On cible NGINX (Port 8000) et non plus le conteneur directement
AUTH_API_URL = "http://localhost:8000/api/auth/login"

def simulate_brute_force(attempts=15): # On augmente à 15 tentatives
    print(f"--- Démarrage de l'attaque Brute Force : {attempts} tentatives ---")
    
    for i in range(1, attempts + 1):
        payload = {
            "username": "admin", 
            "password": f"wrong_password_{i}" 
        }
        
        try:
            response = requests.post(AUTH_API_URL, json=payload, timeout=2)
            
            # On affiche clairement si NGINX a intercepté la requête
            if response.status_code == 429:
                print(f"Tentative {i} : 🛡️ BLOQUÉ PAR NGINX (429 Too Many Requests) !")
            elif response.status_code == 401:
                print(f"Tentative {i} : ❌ Échec de connexion (401 Unauthorized)")
            else:
                print(f"Tentative {i} : Statut {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print(f"Tentative {i} : 💥 Connexion refusée (Le port 8000 est-il ouvert ?)")
        except Exception as e:
            print(f"Tentative {i} : Erreur -> {e}")
        
        # 2. On réduit le délai à 0.2s (5 requêtes/sec) pour déclencher le Rate Limiting
        time.sleep(0.2)

    print("--- Simulation terminée ---")
    print("Regarde ton Discord dans 10 secondes et vérifie que ton Dashboard est toujours en ligne !")

if __name__ == "__main__":
    simulate_brute_force()
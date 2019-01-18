**SIMPLE DOCKER REST-API**
-----------------------------------------
**USAGE:**

./dagent

=> List (GET) 
	
	-----------------------
	FROM BROWSER
	-----------------------
	
	- /containers
	- /images
	- /volumes
	- /networks
	- /services
	- /nodes
	 
	-------------------------
	STOP/START (POST)
	-------------------------
	- /containers/{id}/stop
	- /containers/{id}/start

	-------------------------------- 
	FOR API REQUESTS - JSON RESPONSE
	--------------------------------- 

	- /api/containers | /api/containers/{container_id}
	- /api/images | /api/images/{image_id}
	- /api/volumes | /api/volumes/{volume_id}
	- /api/networks | /api/networks/{network_id}
	- /api/services | TODO for individual
	- /api/nodes | TODO for individual

**TODO**
 - Containerize process in custom-made container
 - TLS
 - Token generation for API access over script
 - Basic User/Pass auth
 - Refactor 
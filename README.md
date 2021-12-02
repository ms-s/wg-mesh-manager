# wg-mesh-manager
Wireguard mesh configuration file manager API in python Flask

Based on meshmash https://github.com/nickpegg/meshmash


API descirption:

| Request type | URL                                       |Request Body        |Response body
| -----------  | ------------------------------------------|--------------------|-------------------
| POST         | /overlays                                 |                    |
| GET          | /overlays                                 |                    |
| GET          | /overlays/<overlay_id>                    |                    |
| POST         | /devices                                  |                    |
| GET          | /devices                                  |                    |
| GET          | /devices/<device_id>                      |                    |
| PUT          | /devices/<device_id>                      |                    |
| DELETE       | /overlays/<overlay_id>                    |                    |
| DELETE       | /devices/<device_id>                      |                    |
| POST         | /overlays/<overlay_id>/devices            |                    |
| POST         | /overlays/<overlay_id>/devices/<device_id>|                    |
| DELETE       | /overlays/<overlay_id>/devices/<device_id>|                    |
| GET          | /devices/<device_id>/token                |                    |

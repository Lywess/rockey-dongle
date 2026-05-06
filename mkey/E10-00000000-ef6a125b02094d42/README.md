## E10 初始化过程,  初始化为 EnTrust-Null 模式 ...
- 导入 SESSION-KEY, 签署 SESSION_KEY_SIGNATURE 后锁定 u-key ...
```json
[
{
  "category": 3277357231,
  "SM2ECDSA": "kRViR+tKFpce3XJEbVCVe6i+oL7z3/sQSDnIf4ieL/VThbAULRedSvh15rOcxTppKnirisLq2YRDKS69jXBFyA==",
  "P256ECDSA": "TbuZIG0g/vXe0w/WNRuYRq95E+ZFOctI+aJ9teZPmWpjntIP3YOt2PrK8V27o+xZhWjG4QybKj4QNiKUYo/PnA==",
  "RSA2048": "AQABANxIGmVIViRiSdbipKkPzLyqTi2d+Z6InmEfvuamNaYkDtbfzB37N4kf302Nspxm7dNtQ6+4K4h5cCSXcROZSNeC4todpAluJIqUWxXBnmcrEAe1Kvg1eB6kaeiPs0huk3Tm5ROyrjCpK5hVq80i0MKhLkSn8tDISGSj7Vov7U8sc0gsLU9/96mg0C1e+ksUBhPAUOXi0zDB1PCdKAp4xgnO0pQBOtkJqRcmELYGAz0KSuNoqTH6WquttcShfE1/4/1gECn1S1d1/L0zwZCcMloAAdzN7ASkpj4xDayMbsQ93Ock7Q9xQxoG3ZP6aXs+f6KGpCdQXa28L8q2ccpNydE=",
  "SM2ECIES": "lpVCPHkAix4gM7ENGldY/7OQoVJLITsXep1JsRRpg4mKLL3mlKxAG/laJ3y1p8WnnPEAFOygI7q9c+g3xsHhug==",
  "nonce_local": "Ao5aBXOR2NyZI3dGq9Yhe5ZMpQxJxrXuRTb9qZX09ss=",
  "dongle": {
    "id": "00000000-ef6a125b02094d42",
    "pid": "0x0b3cef16",
    "uid": "0x00000e10",
    "type": "0x000000ff",
    "birthday": "2024-11-26 19:47:36",
    "agent": "0xffffffff",
    "version": "0x00000222"
  },
  "nonce_admin": "wCpQzk5kj0UkC9OkwfXVm7jsUxMmtNEurS6zctbYdFk=",
  "EnTrust": [
    "df482a",
    "AAAAAO9qElsCCU1C30gqAJEVYkfrShaXHt1yRG1QlXuovqC+89/7EEg5yH+Ini/1U4WwFC0XnUr4deaznMU6aSp4q4rC6tmEQykuvY1wRcg="
  ]
},
[
  null,
  null,
  null,
  null,
  null
]
]
```
- 锁定 u-key 记录
```text
-----BEGIN PGP MESSAGE-----

hF4D0x6ByAWYN4USAQdAEH78QVl5P49hEtcy7/rGUUh+z+bSXUqh/rkssgnaFwgw
JCN+cFOy7KIc4RgN5tMQC/nmrEc1s5TLGfBYge5FatR+q6lt/E+C6Q1z7W6bKJJ7
1OkBCQIQx1/9LHhaF5gTAnnDd9UdDiLzHsmD+8sy/9sh+0KgHt1RBAZ3u5V6Cr/T
IAOcgNFSXIaeMKp7C71Dr8sUBntbtBp/vnCn3EkMsIUvwHH4oeRx7Xoe3GkJhX+n
2fGYU7kwx0nkYbF13cg4EKrrI9qtF1ijX4xGWxcXKfv2evyDPx8c68XDlsKOF3Uu
3PnVFrsP6pS0T7KRQJsnP9RsM/XQwyzQwr9LUocA/QjUOBf6tbWHyfeuTJ441+m+
EBvwj2C7Q8WHnz27zdUYlE3k235RMTj/D58LljBMIiYG60sAGmSug8ZlD2HJkEpd
S7YR4bXTn411Y4OrE7t8K1ScVA6s3iFZ7eDoNsuAhQ6o+sF+5Aby5mULJGIZdP1l
1vHMNq6oa1TALf3RctQbhVp6PerjymvMN8DQz3BRX75ns8n9RVE2LhxTOe9ivLCH
Xq2L2ocp1GiIZVHuME5Y/nh0y0xfUQDoReNm8LTZotne6ls8sUWKSOEzXXURauee
ZGNt7Ga30uAn9E+gVaslz+D53X6dY2p03iJO/yXc9dfwTWNiSm+CHpzxmhkTWN0o
S9jBIgXr1zJkIBIiytDh6UAP+i3Xmm9mCqpbYcaWQsPbcDmDf6S9Pp84iPi0XiE1
sQcCqdeEBcS0T050FPaTXhc4Yns91vP3hI6C5PeyyAyqH7aeDBZe2qlKjDF54vSW
FPmsmPADfoU+6PNxG+0k4i8VK07G5oDqQMrFLqV1gyDVffFT6UGH6+f3WGHiQZ3n
BY68zeSyRB9Ay1KG/sEB42mouFXwwvT5W/tuQhgnQ/7n1Izpu5+nFnb7+YTMLueQ
U8a365mnXshUi88rNHnr+uf/V5z/b5r/A+kd+0nyEy74HByM8gQTQsNoxSB9ZeIv
GcpwFSGqCcR5NVRPyxF/va5Ow8FmmMLDoA==
=oBT6
-----END PGP MESSAGE-----
```

# C4BEP1

#### 介绍
随着网络技术的快速发展，网络规模的增大和应用数量的逐渐增加，使得用户对网络服
务质量的保障提出了新的要求，需要高效的路由算法来保障业务流的服务质量(QoS)需求。
但是传统的网络架构过于复杂，难以获取全局视图，受到了路由算法的设计和应用的限制，
无法提供理想的 QoS 服务。
软件定义网络(Software Defined Network, SDN)架构的提出解决了控制平面和数据平面
的耦合问题，为 QoS 路由提供了新的思路。使用 SDN 架构，可以根据 QoS 策略在控制平
面实现对应的路由算法，并通过 OpenFlow 协议在数据平面上安装相应的流表。同时，机
器学习算法的广泛应用也为 SDN 网络中的 QoS 路由优化带来了新的研究方向。
我们提出“基于 SDN 和机器学习的业务流 Qos 保障系统”，其核心是在 SDN 网络基础上
利用机器学习实现流量预测和分类，进而实现 Qos 路由和差异化限速。该系统可以检测和
排除异常流量，提供先见性的流量预测，并实现对路由的自动调整，从而为网络中的业务流
传输提供保障，同时提供更加理想的 Qos 服务。
本系统结合了 SDN 和机器学习技术，将二者有机地结合，从而实现了对网络中业务流
的精细化控制，为网络中的各种应用提供了更加理想的 QoS 服务。其次，该系统利用机器
学习技术实现了对异常流量的检测和排除，提高了网络的可靠性和稳定性，同时提升了网络
的安全性能。最后，该系统实现了对路由的自动调整，可以根据流量预测和分类结果对网络
路由进行动态调整，从而进一步提高网络的质量和性能，为用户提供更加优质的服务。

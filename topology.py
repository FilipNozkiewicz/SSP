class MyTopo( Topo ):
    "Topology to test elephant flow detection."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        leftHost = self.addHost( 'h1' )
        rightHost = self.addHost( 'h2' )

        switch1 = self.addSwitch( 's1' )
        switch2 = self.addSwitch( 's2' )
        switch3 = self.addSwitch( 's3' )
        switch4 = self.addSwitch( 's4' )
        switch5 = self.addSwitch( 's5' )

        # Add links
        self.addLink( leftHost, switch1 )
        self.addLink( switch5, rightHost )
        self.addLink( switch1, switch2 )
        self.addLink( switch1, switch3 )
        self.addLink( switch1, switch4 )
        self.addLink( switch2, switch5 )
        self.addLink( switch3, switch5 )
        self.addLink( switch4, switch5 )

topos = { 'mytopo': ( lambda: MyTopo() ) }


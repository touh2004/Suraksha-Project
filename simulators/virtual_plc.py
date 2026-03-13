# simulators/virtual_plc.py
import asyncio
import logging
from pymodbus.server import StartAsyncTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext

# Isse humein terminal mein live packets aate hue dikhenge!
logging.basicConfig(level=logging.INFO)

async def run_virtual_plc():
    print("🏭 Initializing Factory Machine: PLC-01 (Main Conveyor)...")
    
    # 1. CREATE VIRTUAL MEMORY (Registers & Coils)
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0]*100), # Discrete Inputs
        co=ModbusSequentialDataBlock(0, [1]*100), # Coils (1 = Machine is Running)
        hr=ModbusSequentialDataBlock(0, [0]*100), # Holding Registers
        ir=ModbusSequentialDataBlock(0, [0]*100)  # Input Registers
    )
    context = ModbusServerContext(slaves=store, single=True)

    # 2. START THE SERVER ON PORT 5020
    print("🌐 VIRTUAL PLC ONLINE: Listening on 0.0.0.0:5020 (Modbus TCP)")
    print("⚠️ Warning: System is vulnerable. No authentication enabled.")
    
    # Starting the async TCP server (Removed the identity part causing the error)
    await StartAsyncTcpServer(context=context, address=("0.0.0.0", 5020))

if __name__ == "__main__":
    try:
        # Windows compatibility for asyncio
        import sys
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            
        asyncio.run(run_virtual_plc())
    except KeyboardInterrupt:
        print("\n🛑 Virtual PLC Shut Down.")
// fw/hdl/boot_rom.v — ТП SAKURA-7T-TP §27.10 (secure boot ROM stub)
module boot_rom #(
    parameter ADDR_W = 12,
    parameter DATA_W = 32
) (
    input  wire              clk,
    input  wire              rst_n,
    input  wire [ADDR_W-1:0] addr,
    output reg  [DATA_W-1:0] data,
    output reg               valid
);
    reg [DATA_W-1:0] rom [0:(1<<ADDR_W)-1];

    initial begin
        $readmemh("boot_rom.hex", rom);
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            data  <= {DATA_W{1'b0}};
            valid <= 1'b0;
        end else begin
            data  <= rom[addr];
            valid <= 1'b1;
        end
    end
endmodule

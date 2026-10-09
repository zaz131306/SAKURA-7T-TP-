// fw/hdl/window_wdt.v — ТП SAKURA-7T-TP §22.11 (C-05, исправленная редакция)
// Свойства: kick в границе [MIN, MAX] включительно валиден; после валидного
// kick окно перезапускается; timeout защёлкнут (sticky) до аппаратного
// сброса; после просрочки подсчёт остановлен.
module window_wdt #(
    parameter CLK_HZ = 100_000_000,
    parameter MIN_MS = 50,
    parameter MAX_MS = 200
) (
    input  wire clk,
    input  wire rst_n,
    input  wire kick,
    output reg  timeout      // sticky: снимается только аппаратным сбросом
);
    localparam MIN_CYCLES = (CLK_HZ / 1000) * MIN_MS;
    localparam MAX_CYCLES = (CLK_HZ / 1000) * MAX_MS;

    reg [31:0] counter;
    reg        armed;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            counter <= 32'd0;
            armed   <= 1'b1;
            timeout <= 1'b0;
        end else if (kick) begin
            if (armed && counter < MIN_CYCLES) begin
                timeout <= 1'b1;
            end else begin
                counter <= 32'd0;
                armed   <= 1'b1;
            end
        end else if (armed && counter >= MAX_CYCLES) begin
            timeout <= 1'b1;
            armed   <= 1'b0;
        end else begin
            counter <= counter + 32'd1;
        end
    end
endmodule
